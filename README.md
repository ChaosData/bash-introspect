# bash-introspect

A native bash builtin module for extracting bash inputs.

# Building

```
$ gcc -std=c11 -Wall -Wextra -shared -fpic -o introspect.so introspect.c
```

# Running

```
$ enable -f $PWD/introspect.so introspect
$ introspect
```

# Examples

```
$ bash ./test2.sh
wat
[bash-introspect]
exe: /usr/bin/bash
cmdline: 'bash' './test2.sh'
[bash_input: 0x56464be9f240]
[bash_input.name: ./test2.sh]
[bash_input.type: st_bstream]
[bash_input.location.buffered_fd: 255]
[bash_input.location.buffered_fd.pos: 7365]
[bash_input.location.buffered_fd.len: 7365]
----
unset HISTFILE
if [ -f /tmp/foo ]; then
  echo "this is a secret"
fi
if [ -f /tmp/bar ]; then
  echo "this is also a secret"
fi
################################################################
################################################################
...
################################################################
################################################################
echo "wat"
enable -f $PWD/introspect.so introspect
introspect
echo "post"
################################################################
################################################################
...
################################################################
################################################################

echo "done"
----
post
done
```

```
$ bash < ./test2.sh
wat
[bash-introspect]
exe: /usr/bin/bash
cmdline: 'bash'
[bash_input: 0x563472cf9240]
[bash_input.name: bash]
[bash_input.type: st_bstream]
[bash_input.location.buffered_fd: 0]
[bash_input.location.buffered_fd.pos: 7365]
[bash_input.location.buffered_fd.len: 7365]
----
unset HISTFILE
if [ -f /tmp/foo ]; then
  echo "this is a secret"
fi
if [ -f /tmp/bar ]; then
  echo "this is also a secret"
fi
################################################################
################################################################
...
################################################################
################################################################
echo "wat"
enable -f $PWD/introspect.so introspect
introspect
echo "post"
################################################################
################################################################
...
################################################################
################################################################

echo "done"
----
post
done
```

```
$ cat test2.sh | bash
wat
[bash-introspect]
exe: /usr/bin/bash
cmdline: 'bash'
[bash_input: 0x55738b413240]
[bash_input.name: bash]
[bash_input.type: st_bstream]
[bash_input.location.buffered_fd: 0]
[dumping prior history]
----
----
[dumping remaining from stdin]
r == 0
----
echo "post"
################################################################
################################################################
...
################################################################
################################################################

echo "done"
----
post
done
```

```
$ echo -e 'enable -f $PWD/introspect.so introspect ; introspect\necho done' | bash
[bash-introspect]
exe: /usr/bin/bash
cmdline: 'bash'
[bash_input: 0x560d19439240]
[bash_input.name: bash]
[bash_input.type: st_bstream]
[bash_input.location.buffered_fd: 0]
[dumping prior history]
----
----
[dumping remaining from stdin]
r == 0
----
echo done
----
done
```
