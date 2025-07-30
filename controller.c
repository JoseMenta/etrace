//
// Created by Jose Menta on 29/07/2025.
//

#include "vmlinux.h" //bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <sys/syscall.h>
#include "controller.h"

const default_syscall_info syscalls[MAX_SYSCALL_NUM] = {
    [SYS_clone] = {"clone", 5},
    [SYS_brk] = {"brk", 1},
    [SYS_close] = {"close", 1},
    [SYS_exit] = {"exit", 1},
    [SYS_exit_group] = {"exit_group", 1},
    [SYS_set_tid_address] = {"set_tid_address", 1},
    [SYS_set_robust_list] = {"set_robust_list", 1},
    [SYS_faccessat] = {"faccessat", 3},
    [SYS_kill] = {"kill", 2},
    [SYS_listen] = {"listen", 2},
    [SYS_munmap] = {"sys_munmap", 2},
    [SYS_openat] = {"openat", 4},
    [SYS_newfstatat] = {"newfstatat", 4},
    [SYS_fstat] = {"fstat", 2},
    [SYS_accept] = {"accept", 3},
    [SYS_connect] = {"connect", 3},
    [SYS_execve] = {"execve", 3},
    [SYS_ioctl] = {"ioctl", 3},
    [SYS_getrandom] = {"getrandom", 3},
    [SYS_lseek] = {"lseek", 3},
    [SYS_ppoll] = {"poll", 5},
    [SYS_read] = {"read", 3},
    [SYS_write] = {"write", 3},
    [SYS_mprotect] = {"mprotect", 3},
    [SYS_openat] = {"openat", 3},
    [SYS_socket] = {"socket", 3},
    [SYS_newfstatat] = {"newfstatat", 4},
    [SYS_pread64] = {"pread64", 4},
    [SYS_prlimit64] = {"prlimit64", 4},
    [SYS_rseq] = {"rseq", 4},
    [SYS_sendfile] = {"sendfile", 4},
    [SYS_socketpair] = {"socketpair", 4},
    [SYS_mmap] = {"mmap", 6},
    [SYS_recvfrom] = {"recvfrom", 6},
    [SYS_sendto] = {"sendto", 6},
};

//Hashmap
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, 10);
    __uint(value_size, 4);
    __uint(max_entries, 256 * 1024);
} pid_hashmap SEC(".maps");

// Ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} syscall_info_buffer SEC(".maps");



SEC("tracepoint/raw_syscalls/sys_enter")
int detect_syscall_enter(struct trace_event_raw_sys_enter* ctx) {
    long syscall_num = ctx->id;
    const char* key = "child_pid";
    int target_pid;

    void* value = bpf_map_lookup_elem(&pid_hashmap, key);
    void* args[MAX_ARGS] = {0};

    if (value != NULL) {
        target_pid = *(int*) value;
        //pid of the process that executed the syscall
        pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
        if (pid == target_pid && syscall_num >= 0 && syscall_num < MAX_SYSCALL_NUM) {
            int idx = syscall_num;
            inner_syscall_info* info = bpf_ringbuf_reserve(&syscall_info_buffer, sizeof(inner_syscall_info), 0);
            if (!info) {
                bpf_printk("bpf_ringbuf_reserve failed\n");
                return 1;
            }

            //copy syscall name into info->name
            bpf_probe_read_kernel_str(info->name, sizeof(syscalls[syscall_num].name), syscalls[syscall_num].name);
            //copy args
            for (int i = 0;  i < MAX_ARGS; i++) {
                info->args[i] = (void*) BPF_CORE_READ(ctx, args[i]);
            }
            info->num_args = syscalls[syscall_num].num_args;
            info->syscall_num = syscall_num;
            info->mode = SYS_ENTER;

            //Insert in ring buffer
            bpf_ringbuf_submit(info, 0);

        }
    }
    return 0;
}


