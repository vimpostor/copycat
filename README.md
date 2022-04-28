# Copycat

This project is meant to provide an easily usable library for overwriting system calls.


For example consider a program called "weird-program" that uses a hardcoded config path and opens it at runtime, let's say that config is `/etc/config`. Now suppose that you want it to use another config file and don't have much time on your hand and don't like beating around the bush, so you absolutely don't want to edit the source code of that program and recompile it.
Instead with this library you can now do the following:

```bash
# Note that the syntax will probably change in the future
COPYCAT="/etc/config $HOME/.new-local-config" copycat -- weird-program
```

Tada, "weird-program" will now successfully use your new local config despite the hardcoded config and completely without recompiling. :partying_face:

## How does this work?

The way that this is implemented at the moment, is by intercepting the `openat()` system call using `LD_PRELOAD` and `dlsym()`. This has effectively no performance impact but the disadvantage is that it will not work with all binaries (e.g. not with statically linked binaries).

To make this work for all binaries, I intend to implement optional `ptrace` support in the future, which would also work for static binaries, but would be much slower (much like running the binary through a debugger).

If you'd like to test it out, you can install the [copycat-git](https://aur.archlinux.org/packages/copycat-git) package from the AUR.