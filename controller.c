//
// Created by Jose Menta on 29/07/2025.
//

#include "vmlinux.h" //bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "controller.h"


#define MIN(a,b) (((a) < (b)) ? (a) : (b))

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

    void* value = bpf_map_lookup_elem(&pid_hashmap, key);

    if (value != NULL) {
        const int target_pid = *(int*)value;
        //pid of the process that executed the syscall
        const pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
        if (pid == target_pid && syscall_num >= 0 && syscall_num < MAX_SYSCALL_NUM) {
            const int idx = syscall_num;
            inner_syscall_info* info = bpf_ringbuf_reserve(&syscall_info_buffer, sizeof(inner_syscall_info), 0);
            if (!info) {
                bpf_printk("bpf_ringbuf_reserve failed\n");
                return 1;
            }

            //copy syscall name into info->name
            bpf_probe_read_kernel_str(info->name, sizeof(syscalls[syscall_num].name), syscalls[syscall_num].name);

            //Yes, this should be a call to a function (as I tried below), BUT the eBPF verifier isn't able to check
            //that the use of ctx inside the function is correct. By copying the logic of the functions inside this function
            //the verifier is able to check the program.
            //If you find a better solution, let me know or open a PR.
            switch (idx) {
            case SYS_write:
                // Logic for read_for_sys_write
                info->args[0].type = VAL_UINT;
                info->args[0].uint_val =  BPF_CORE_READ(ctx, args[0]);

                info->args[2].type = VAL_SIZE_T;
                info->args[2].size_t_val =  BPF_CORE_READ(ctx, args[2]);
                const size_t count = info->args[2].size_t_val;

                info->args[1].type = VAL_STR;
                bpf_probe_read_user_str(info->args[1].str_val, MIN(count, MAX_STRING_LENGTH), (void *) BPF_CORE_READ(ctx, args[1]));
                break;
            default:
                // Logic for read_standard
                // IMPORTANT: Limit to 6 arguments (args[0] to args[5]) as trace_event_raw_sys_enter->args
                // typically contains only 6 elements.
                for (int i = 0; i < 6 && i < syscalls[idx].num_args; i++) {
                    switch (syscalls[idx].types[i]) {
                    case VAL_SIZE_T:
                        info->args[i].type = VAL_SIZE_T;
                        info->args[i].size_t_val = BPF_CORE_READ(ctx, args[i]);
                        break;
                    case VAL_LONG:
                        info->args[i].type = VAL_LONG;
                        info->args[i].long_val = (long) BPF_CORE_READ(ctx, args[i]);
                        break;
                    case VAL_INT:
                        info->args[i].type = VAL_INT;
                        info->args[i].int_val = (int) BPF_CORE_READ(ctx, args[i]);
                        break;
                    case VAL_STR:
                        info->args[i].type = VAL_STR;
                        bpf_probe_read_user_str(info->args[i].str_val, MAX_STRING_LENGTH, (void *) BPF_CORE_READ(ctx, args[i]));
                        break;
                    case VAL_UINT:
                        info->args[i].type = VAL_UINT;
                        info->args[i].uint_val = (unsigned int) BPF_CORE_READ(ctx, args[i]);
                        break;
                    case VAL_ULONG:
                        info->args[i].type = VAL_ULONG;
                        info->args[i].ulong_val = BPF_CORE_READ(ctx, args[i]);
                        break;
                    default: //VAL_PTR
                        info->args[i].type = VAL_PTR;
                        info->args[i].ptr_val = (void *) BPF_CORE_READ(ctx, args[i]);
                        break;
                    }
                }
                break;
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

    if (value != NULL) {
        //We only want to trace the syscalls of the process with the pid in the map
        const pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
        const pid_t target_pid = *(pid_t*)value;

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



// inline int read_for_sys_write(inner_syscall_info* info, struct trace_event_raw_sys_enter* ctx, const int id) {
//     info->args[0].type = VAL_UINT;
//     info->args[0].uint_val =  BPF_CORE_READ(ctx, args[0]);
//
//     info->args[2].type = VAL_SIZE_T;
//     info->args[2].size_t_val =  BPF_CORE_READ(ctx, args[2]);
//     const size_t count = info->args[2].size_t_val;
//
//     info->args[1].type = VAL_STR;
//     bpf_probe_read_user_str(info->args[1].str_val, MIN(count, MAX_STRING_LENGTH), (void *) BPF_CORE_READ(ctx, args[1]));
//
//     return 0;
// }
//
// //With designated initializers, the rest of the elements are zero (null)
// //Add any reader for a custom method to read the arguments for a syscall
// //Do not use now because function pointers are not supported
// // reader_type readers[MAX_SYSCALL_NUM] = {
// //     [SYS_write] = read_for_sys_write
// // };
//
//
// inline int read_standard(inner_syscall_info* info, struct trace_event_raw_sys_enter* ctx, const int id) {
//     for (int i = 0; i < MAX_ARGS && i < syscalls[id].num_args; i++) {
//         switch (syscalls[id].types[i]) {
//         case VAL_SIZE_T:
//             info->args[i].type = VAL_SIZE_T;
//             info->args[i].size_t_val = BPF_CORE_READ(ctx, args[i]);
//             break;
//         case VAL_LONG:
//             info->args[i].type = VAL_LONG;
//             info->args[i].long_val = (long) BPF_CORE_READ(ctx, args[i]);
//             break;
//         case VAL_INT:
//             info->args[i].type = VAL_INT;
//             info->args[i].int_val = (int) BPF_CORE_READ(ctx, args[i]);
//             break;
//         case VAL_STR:
//             info->args[i].type = VAL_STR;
//             bpf_probe_read_user_str(info->args[i].str_val, MAX_STRING_LENGTH, (void *) BPF_CORE_READ(ctx, args[i]));
//             break;
//         case VAL_UINT:
//             info->args[i].type = VAL_UINT;
//             info->args[i].uint_val = (unsigned int) BPF_CORE_READ(ctx, args[i]);
//             break;
//         case VAL_ULONG:
//             info->args[i].type = VAL_ULONG;
//             info->args[i].ulong_val = BPF_CORE_READ(ctx, args[i]);
//             break;
//         default: //VAL_PTR
//             info->args[i].type = VAL_PTR;
//             info->args[i].ptr_val = (void *) BPF_CORE_READ(ctx, args[i]);
//             break;
//         }
//     }
//     return 0;
// }
//
// inline void read_args(inner_syscall_info* info, struct trace_event_raw_sys_enter* ctx, const int id) {
//     //Add other custom readers here
//     switch (id) {
//     case SYS_write:
//         read_for_sys_write(info, ctx, id);
//         break;
//     default:
//         read_standard(info, ctx, id);
//         break;
//     }
// }

char LICENSE[] SEC("license") = "GPL";