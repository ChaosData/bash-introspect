/*
Copyright (c) 2021 NCC Group Security Services, Inc. All rights reserved.
Licensed under Dual BSD/GPLv3 per the repo LICENSE file.
*/

// $ gcc -std=c11 -Wall -Wextra -shared -fpic -o introspect.so introspect.c
// $ enable -f $PWD/introspect.so introspect
// $ introspect

#define _POSIX_C_SOURCE 200112L
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//#include <readline/history.h>

/* Flags describing various things about a builtin. */
#define BUILTIN_ENABLED 0x01	/* This builtin is enabled. */
#define BUILTIN_DELETED 0x02	/* This has been deleted with enable -d. */
#define STATIC_BUILTIN  0x04	/* This builtin is not dynamically loaded. */
#define SPECIAL_BUILTIN 0x08	/* This is a Posix `special' builtin. */
#define ASSIGNMENT_BUILTIN 0x10	/* This builtin takes assignment statements. */
#define POSIX_BUILTIN	0x20	/* This builtins is special in the Posix command search order. */
#define LOCALVAR_BUILTIN   0x40	/* This builtin creates local variables */

#define EX_USAGE	258	/* syntax error in usage */

/* Values that can be returned by execute_command (). */
#define EXECUTION_FAILURE 1
#define EXECUTION_SUCCESS 0

struct builtin {
  char *name;			/* The name that the user types. */
  void *function;		/* The address of the invoked function. */
  int flags;			/* One of the #defines above. */
  char * const *long_doc;	/* NULL terminated array of strings. */
  const char *short_doc;	/* Short version of documentation. */
  char *handle;			/* for future use */
};

typedef union {
  FILE *file;
  char *string;
  int buffered_fd;
} INPUT_STREAM;

enum stream_type {st_none, st_stdin, st_stream, st_string, st_bstream};

char const* st_none_str = "st_none";
char const* st_stdin_str = "st_stdin";
char const* st_stream_str = "st_stream";
char const* st_string_str = "st_string";
char const* st_bstream_str = "st_bstream";
char const* st_unknown_str = "st_unknown";

typedef struct {
  enum stream_type type;
  char *name;
  INPUT_STREAM location;
  int (*getter)();
  int (*ungetter)();
} BASH_INPUT;

typedef struct _hist_entry {
  char *line;
  char *timestamp;
  char* data;
} HIST_ENTRY;

extern HIST_ENTRY** history_list();
extern int history_offset;
extern int history_length;

extern BASH_INPUT bash_input;
extern int __attribute__((weak)) default_buffered_input;

extern char* command_execution_string;
extern int read_from_stdin;

extern char* __attribute__((weak)) current_readline_line;

extern int show_all_var_attributes(int v, int nodefs);

typedef struct variable {
  char *name;			/* Symbol that the user types. */
  char *value;			/* Value that is returned. */
  char *exportstr;		/* String for the environment. */
  void *dynamic_value;	/* Function called to return a `dynamic'
				   value for a variable, like $SECONDS
				   or $RANDOM. */
  void *assign_func; /* Function called when this `special
				   variable' is assigned a value in
				   bind_variable. */
  int attributes;		/* export, readonly, array, invisible... */
  int context;			/* Which context this variable belongs to. */
} SHELL_VAR;
extern SHELL_VAR** all_shell_functions();

char const* get_type(BASH_INPUT* b) {
  switch (b->type) {
    case st_none:
      return st_none_str;
    case st_stdin:
      return st_stdin_str;
    case st_stream:
      return st_stream_str;
    case st_string:
      return st_string_str;
    case st_bstream:
      return st_bstream_str;
    default:
      return st_unknown_str;
  }
}

void dump_hist() {
  puts("[dumping prior history]");
  HIST_ENTRY** hist = history_list();
  puts("----");
  for (int i=0; i < history_length; i++) {
    printf("%s\n", hist[i]->line);
  }
  puts("----");

}

void dump_stdin() {
  dump_hist();
  puts("[dumping remaining from stdin]");

  int fds[2];
  if (pipe(fds) != 0) {
    perror("pipe");
    return;
  }

  size_t bufsz = 4096;
  size_t csz = 0;
  char* buf = (char*)malloc(bufsz);

  while (1) {
    ssize_t r = read(0, &buf[csz], bufsz-csz-1);
    if (r <= 0) {
      if (r == 0) {
        puts("r == 0");
      } else {
        perror("read");
      }
      break;
    }
    csz += (size_t)r;

    if ((csz+1) == bufsz) {
      bufsz *= 2;
      buf = (char*)realloc(buf, bufsz);
    }
  }
  buf[csz] = '\0';

  close(0);
  dup2(fds[0], 0);
  write(fds[1], buf, csz);
  close(fds[1]);
  if (buf[csz-1] == '\n') {
    printf("----\n%s----\n", buf);
  } else {
    printf("----\n%s\n%%----\n", buf);
  }

}

void dump_getter() {
  dump_hist();

  puts("[dumping remaining from bash_input.getter()]");

  size_t bufsz = 4096;
  size_t csz = 0;
  char* buf = (char*)malloc(bufsz);

  while (1) {
  //for (size_t ii=0; ii<4096; ii++) {
    int ch = bash_input.getter();
    if (ch <= 0) {
      break;
    }
    buf[csz] = (char)ch;
    csz += 1;

    if ((csz+1) == bufsz) {
      bufsz *= 2;
      buf = (char*)realloc(buf, bufsz);
    }
  }

  /*for (size_t i=csz; i > 0; i--) {
    bash_input.ungetter(buf[i-1]);
  }*/

  buf[csz] = '\0';

  int fds[2];
  if (pipe(fds) != 0) {
    perror("pipe");
    return;
  }

  close(0);
  dup2(fds[0], 0);
  write(fds[1], buf, csz);
  close(fds[1]);

  if (buf[csz-1] == '\n') {
    printf("----\n%s----\n", buf);
  } else {
    printf("----\n%s\n%%----\n", buf);
  }

}

void dump_proc_info() {
  //pid_t pid = getpid();
  //printf("pid: %d\n", pid);
  {
    char linkbuf[PATH_MAX];
    ssize_t r = readlink("/proc/self/exe", linkbuf, sizeof(linkbuf));
    if (r < 0) {
      perror("readlink(\"/proc/self/exe\")");
    } else {
      printf("exe: %s\n", linkbuf);
    }
  }
  {
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) {
      perror("open(\"/proc/self/cmdline\")");
    } else {
      char cmdline[131072];
      int r = read(fd, cmdline, sizeof(cmdline));
      if (r < 0) {
        perror("read(\"/proc/self/cmdline\")");
      } else {
        printf("%s", "cmdline: ");
        for (int i=0; i < r; i++) {
          if (i == 0) {
            printf("'");
          }
          if (cmdline[i] == '\0') {
            if (i+1 == r) {
              break;
            }
            printf("%s", "' '");
          } else {
            if (cmdline[i] == '\'') {
              printf("%s", "'\\''");
            } else {
              putchar(cmdline[i]);
            }
          }
        }
        puts("'");
      }
    }
  }
}

void introspect() {
  //printf("default_input: %p\n", default_input);
  printf("[bash_input: %p]\n", (void*)&bash_input);
  printf("[bash_input.name: %s]\n", bash_input.name);
  printf("[bash_input.type: %s]\n", get_type(&bash_input));
  //printf("[read_from_stdin: %d]\n", read_from_stdin);

  switch (bash_input.type) {
    case st_none: {
      break;
    }
    case st_stdin: {
      // echo 'enable -f $PWD/introspect.so introspect ; introspect ; echo done' | bash --noprofile -i
      dump_stdin();
      break;
    }
    case st_stream: {
      // echo 'enable -f $PWD/introspect.so introspect ; introspect ; echo done' | bash --noprofile --noediting -i
      // cat test2.sh | bash --noprofile --noediting -i
      // bash --noprofile --noediting -i < test.sh
      // bash --noprofile --noediting -i < test2.sh

      FILE* f = bash_input.location.file;
      printf("[bash_input.location.file: %p]\n", (void*)f);
      if (f == (FILE*)0xff || f == NULL) {
        break;
      }

      off_t pos = ftell(f);
      if (pos < 0) {
        //perror("ftell"); // illegal seek
        if (read_from_stdin) {
          //dump_stdin();
          //char buf[1024] = {0};
          //fgets(buf, 1024, f);
          //printf("test: %s\n", buf);
          //printf("bash_input.location.string: %s\n", bash_input.location.string);
          //printf("shell_input_line: %s\n", shell_input_line);
          //dump_string_saver();
          //printf("test3: current_readline_line: %s\n", current_readline_line);
          //write_history("/tmp/yolo.hist");
          dump_getter();
        }
        break;
      }

      printf("[bash_input.location.file.pos: %ld]\n", pos);
      if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek(f, 0, SEEK_END)");
        break;
      }
      off_t len = ftell(f);

      if (pos == 0 && len == 0) {
        // allowing this to continue and fseek to 0 would cause an infinite loop
        puts("weirdness");
        break;
      }

      printf("[bash_input.location.file.len: %jd]\n", len);

      if (fseek(f, 0, SEEK_SET) != 0) {
        perror("fseek(f, 0, SEEK_SET)");
        break;
      }
      char* buf = (char*)malloc(len+1);
      fread(buf, 1, len, f);
      buf[len] = '\0';
      if (fseek(f, pos, SEEK_SET) != 0) {
        perror("fseek(f, pos, SEEK_SET)");
        break;
      }
      if (buf[len-1] == '\n') {
        printf("----\n%s----\n", buf);
      } else {
        printf("----\n%s\n%%----\n", buf);
      }
      break;
    }
    case st_string: {
      // bash --noprofile -c 'enable -f $PWD/introspect.so introspect ; introspect ; echo done'
      if (bash_input.location.string != (char*)0xff && bash_input.location.string != NULL) {
        if (bash_input.location.string[0] == '\0') {
          printf("command_execution_string: %s\n", command_execution_string);
        } else {
          printf("[bash_input.location.string: %s]\n", bash_input.location.string);
        }
      }
      break;
    }
    case st_bstream: {
      // echo 'enable -f $PWD/introspect.so introspect ; introspect ; echo done' | bash --noprofile
      // cat test2.sh | bash --noprofile --noediting -i
      // bash --noprofile ./test.sh
      // bash --noprofile ./test2.sh

      int fd = bash_input.location.buffered_fd;
      //printf("bash_input.location.buffered_fd: %d\n", fd);
      //printf("default_buffered_input: %d\n", default_buffered_input);
      if (fd < 0) {
        fd = default_buffered_input;
      }
      printf("[bash_input.location.buffered_fd: %d]\n", fd);


      off_t pos = lseek(fd, 0, SEEK_CUR);
      if (pos < 0 && fd == 0 && read_from_stdin) {
        dump_stdin();
        break;
      }

      off_t len = lseek(fd, 0, SEEK_END);

      printf("[bash_input.location.buffered_fd.pos: %jd]\n", pos);
      printf("[bash_input.location.buffered_fd.len: %jd]\n", len);

      off_t r = lseek(fd, 0, SEEK_SET);
      if (r < 0) {
        perror("lseek(SEEK_SET)");
        break;
      }
      char* buf = (char*)malloc(len+1);
      read(fd, buf, len);
      buf[len] = '\0';
      lseek(fd, pos, SEEK_SET);
      if (buf[len-1] == '\n') {
        printf("----\n%s----\n", buf);
      } else {
        printf("----\n%s\n%%----\n", buf);
      }

      break;
    }
    default: {
      break;
    }
  }
}

int introspect_wrapper(void* list) {
  if (list != NULL) {
    fflush(stdout);
    return (EXECUTION_FAILURE);
  }

  puts("<introspect>");
  dump_proc_info();
  introspect();

  puts("[functions]");
  int r = show_all_var_attributes(0, 0);
  (void)r;
  //printf("r: %d\n", r);

  //SHELL_VAR** vs = all_shell_functions();
  //printf("vs: %p\n", (void*)vs);

  puts("[variables]");
  r = show_all_var_attributes(1, 0);
  puts("</introspect>");

  fflush(stdout);
  return (EXECUTION_SUCCESS);
}


char *introspect_doc[] = {
  "introspect",
  "Usage : introspect",
  "Description :",
  "dump stuff",
  (char *)NULL
};

struct builtin introspect_struct = {
  "introspect", // builtin name
  (void*)introspect_wrapper, // function implementing the builtin
  BUILTIN_ENABLED, // initial flags for builtin
  introspect_doc, // array of long documentation strings
  "Usage : introspect", // usage synopsis; becomes short_doc
  NULL // reserved for internal use
};

/*
int introspect_builtin_load (char* s) {
  puts("introspect loaded\n");
  fflush (stdout);
  return (1);
}

void introspect_builtin_unload (char *s) {
  puts("introspect unloaded\n");
  fflush (stdout);
}
*/
