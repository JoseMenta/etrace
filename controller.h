//
// Created by Jose Menta on 29/07/2025.
//

#ifndef CONTROLLER_H
#define CONTROLLER_H

#include "syscall_numbers.h"


#define MAX_ARGS 6
#define MAX_SYSCALL_NUM 335
#define NAME_MAX_LENGTH 32

typedef enum {
    SYS_ENTER,
    SYS_EXIT
} event_mode;



typedef struct {
    union {
        //For SYS_ENTER
        struct {
            char name[NAME_MAX_LENGTH];
            int num_args;
            long syscall_num;
            void* args[MAX_ARGS];
        };
        //For SYS_EXIT
        long ret_val;
    };
    event_mode mode;
} inner_syscall_info;

typedef struct {
    char name[NAME_MAX_LENGTH];
    int num_args;
} default_syscall_info;

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
    [SYS_socket] = {"socket", 3},
    [SYS_pread64] = {"pread64", 4},
    [SYS_prlimit64] = {"prlimit64", 4},
    [SYS_rseq] = {"rseq", 4},
    [SYS_sendfile] = {"sendfile", 4},
    [SYS_socketpair] = {"socketpair", 4},
    [SYS_mmap] = {"mmap", 6},
    [SYS_recvfrom] = {"recvfrom", 6},
    [SYS_sendto] = {"sendto", 6},
};

#endif //CONTROLLER_H
