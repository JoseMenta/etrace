# eTrace
### An `strace`-like Syscall Tracer built with eBPF.

`eTrace` is a system call tracer for Linux, implemented using eBPF (extended Berkeley Packet Filter) and ring buffers. It allows you to observe system calls made by a specified program, providing insights into its interaction with the kernel.

> [!WARNING]
> This tracer is made for **ARM64 Linux systems**. System call numbers and argument structures can vary significantly across different CPU architectures. Changes to `syscall_numbers.h` and `controller.h` should be added for another architectures.

## Requirements

To build and run `eTrace`, you will need:

* Linux Kernel: Version 4.8 or newer.

* Clang

* Make

* CMake

* `libbpf`

* `bpftool`

## Compilation Steps

1.  **Generate `vmlinux.h`:**
    run the following command in the project's directory.

    ```bash
    sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
    ```

2.  **Configure and Build:**
    Navigate to the project's root directory and run CMake and Make:

    ```bash
    cmake .
    make
    ```

    This will compile the eBPF programs (`controller.o`) and the user-space loader (`etrace`) in the `bin` directory.

## Run

`eTrace` typically requires root privileges to load eBPF programs into the kernel.

To trace a program, run `etrace` followed by the path to the executable you want to trace:

```bash
sudo ./bin/etrace <path_to_program>
```

For example, to trace a simple test program located at `./bin/test`:

```bash
sudo ./bin/etrace ./bin/test
```

## Running without sudo (Unprivileged eBPF)

It is possible to run eBPF programs without `sudo` if your system is configured to allow unprivileged eBPF loading. This is typically controlled by the `kernel.unprivileged_bpf_disabled` sysctl parameter.

To enable unprivileged eBPF loading, you can run:

```bash
sudo sysctl kernel.unprivileged_bpf_disabled=0
```


## Contributions

Contributions are welcome! If you find issues, have suggestions for improvements, or want to add support for other architectures, please feel free to open an issue or submit a pull request.