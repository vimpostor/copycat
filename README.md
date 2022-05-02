# Copycat

This library allows you to overwrite system calls of arbitrary binaries in an intuitive way.
For example the following snippet tricks `cat` into opening another file than was given:
```bash
echo "a" > /tmp/a
echo "b" > /tmp/b
COPYCAT="/tmp/a /tmp/b" copycat -- cat /tmp/a # this will print "b"
# Success! cat was tricked into opening /tmp/b instead of /tmp/a
```

Internally `copycat` uses a modern [Seccomp Notifier](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html) implementation to reliably intercept system calls.
This is cleaner and much faster than usual `ptrace`-based implementations. However due to this relatively new Linux Kernel feature, `copycat` only works on **Linux 5.9** or higher.

# Building

Note: Arch users can install the [copycat-git](https://aur.archlinux.org/packages/copycat-git) AUR package.

`copycat` is built with `cmake`:
```bash
cmake -B build
cmake --build build

# Usage
COPYCAT="source destination" build/copycat -- /path/to/program

# To install
cmake --install build
```

# How does this work?

Historically, system call interception was done using `ptrace()`. This has the disadvantage of being very slow, as `ptrace()` will trigger twice per system call.
Using this method it is also incredibly cumbersome to overwrite system call arguments, and one quickly has to deal with architecture-specific quirks.

Recent advancements in the [Seccomp Notifier](https://people.kernel.org/brauner/the-seccomp-notifier-cranking-up-the-crazy-with-bpf) API have made it possible to intercept any system call in a much more elegant way.
This also offers significant speed improvements, now the performance impact is more like running the application in a container (with `seccomp`) instead of running in a debugger (with `ptrace`).

# Rules format

Rules can be supplied via the `$COPYCAT` environment variable. Alternatively create a file with the name `.copycat.conf` and add the rules, one rule per line.

Rules contain a source and destination that are split by a space. If the source ends with a trailing slash, the rule is recursive, i.e. the source is interpreted as directory and all folders and files within this directory are redirected.
If the destination also ends with a trailing slash, then a directory to directory mapping is created and the prefix is always replaced. If only the source ends with a trailing slash, then all files are mapped to the same location.
Otherwise the rule matches source literally, i.e. the rule matches only the single file with the exact name like source.

## Examples

```bash
# Redirect /tmp/a to /tmp/b
/tmp/a /tmp/b
# Redirect all files and folders in /tmp/f recursively to files and folders in /etc/f
/tmp/f/ /etc/f/
# Redirect all files and folders in /tmp/f to the single file /etc/f
/tmp/f/ /etc/f
```
