# side-strace
Run `strace` on program that is under another debugger

Build:

```sh
make
```

Usage example:

```sh
./sidestrace -o trace.txt gdb yourprogram
# In another terminal
tail -f trace.txt
```

## How does it work?

There are two libraries that are injected through `LD_PRELOAD`:

1. `sidestracestrace.so` is `LD_PRELOAD`-ed into strace, making it server listening on UNIX socket instead of actually tracing other process itself
2. `sidestraceside.so` is `LD_PRELOAD`-ed into another debugger program, intercepting `ptrace` and `wait` so that:
    * Debugger process actually is notified about all syscalls being made by debugged program (all `PTRACE_CONT` requests are replaced with `PTRACE_SYSCALL` before reaching kernel)
    * When debugger process is notified about syscall, it connects to `strace` server and relays `ptrace` calls from `strace` to actual debugger program
    * Debugging event is passed to debugger `sidestraceside.so` has been injected into, in order to let it do own handling (unless this is event that only `sidestraceside.so` has requested, in which case it is hidden from actual debugger)

`sidestrace` binary (built from `sidestracelauncher.c`) just launches instance of `strace` server (with `LD_PRELOAD=sidestracestrace.so` and `SIDESTRACE_SOCKET` environment variables set) and actual debugger program specified in command line (also with `SIDESTRACE_SOCKET` set and this time with `LD_PRELOAD=sidestraceside.so`). Then just waits for its exit to do cleanup (termination of server and removal of sockets)


## Separate "inner" and "outer" view

Specifically for `proot` tracing, there was feature to allow separate view of arguments that program is executing and what actually is being executed. On old devices this could be used as:

```sh
sidestrace -o trace-with-rewritten-args.txt -O trace-with-original-args.txt proot ...
```

However this doesn't work on new kernels, as syscalls are intercepted by `proot` through `SECCOMP_RET_TRAP` and it happens after `SIGTRAP|0x80`, but for `sidestraceside.so` syscall enter event already happened and wont be sent to `strace` again in order to avoid confusing it, yet `sidestraceside.so` shouldn't skip reporting first `SIGTRAP|0x80` as it doesn't know if `PTRACE_EVENT_SECCOMP` will happen or not. You can work that around by turning off modification of syscall arguments from seccomp event in proot:

```sh
PROOT_NO_SECCOMP=1 PROOT_ASSUME_NEW_SECCOMP=1 sidestrace -o trace-with-rewritten-args.txt -O trace-with-original-args.txt proot ...
```

(`PROOT_ASSUME_NEW_SECCOMP=1` variable is specific to Termux fork of `PRoot` and is needed only when `PROOT_NO_SECCOMP=1` is used (as it would be auto-detected otherwise))
