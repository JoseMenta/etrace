//
// Created by Jose Menta on 29/07/2025.
//

#include "vmlinux.h" //bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "controller.h"

//Hashmap
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, 10); //strlen("child_pid") + 1
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
    const long syscall_num = ctx->id;
    const char* key = "child_pid";
    int target_pid;

    void* value = bpf_map_lookup_elem(&pid_hashmap, key);

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

SEC("tracepoint/raw_syscalls/sys_exit")
int detect_syscall_exit(struct trace_event_raw_sys_exit* ctx) {
    const char* key = "child_pid";
    void* value = bpf_map_lookup_elem(&pid_hashmap, key);
    pid_t pid, target_pid;

    if (value != NULL) {
        //We only want to trace the syscalls of the process with the pid in the map
        pid = bpf_get_current_pid_tgid() & 0xffffffff;
        target_pid = *(pid_t*) value;

        if (pid == target_pid) {
            inner_syscall_info *info = bpf_ringbuf_reserve(&syscall_info_buffer, sizeof(inner_syscall_info), 0);
            if (!info) {
                bpf_printk("bpf_ringbuf_reserve failed\n");
                return 1;
            }

            info->mode = SYS_EXIT;
            info->ret_val = ctx->ret;
            bpf_ringbuf_submit(info, 0);
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";