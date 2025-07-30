//
// Created by Jose Menta on 29/07/2025.
//

#ifndef CONTROLLER_H
#define CONTROLLER_H

#include "syscall_numbers.h"


#define MAX_ARGS 6
#define MAX_SYSCALL_NUM 335
#define NAME_MAX_LENGTH 32
//TODO: check why it breaks when using a value higher than 128 
#define MAX_STRING_LENGTH 128

typedef enum {
    SYS_ENTER,
    SYS_EXIT
} event_mode;

typedef enum {
    VAL_SIZE_T,
    VAL_LONG,
    VAL_PTR,
    VAL_INT,
    VAL_STR,
    VAL_UINT,
    VAL_ULONG,
    VAL_NONE
}arg_type;

typedef struct {
    union {
        size_t size_t_val;
        long long_val;
        void* ptr_val;
        int int_val;
        char str_val[MAX_STRING_LENGTH];
        unsigned int uint_val;
        unsigned long ulong_val;
    };

    arg_type type;
}arg_val;


typedef struct {
    union {
        //For SYS_ENTER
        struct {
            char name[NAME_MAX_LENGTH];
            int num_args;
            long syscall_num;
            arg_val args[MAX_ARGS];
        };
        //For SYS_EXIT
        long ret_val;
    };
    event_mode mode;
} inner_syscall_info;

typedef struct {
    char name[NAME_MAX_LENGTH];
    int num_args;
    arg_type types[MAX_ARGS];
    arg_type ret_type;
} default_syscall_info;


//See
//https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#arm64-64_bit
//https://arm64.syscall.sh/

const default_syscall_info syscalls[MAX_SYSCALL_NUM] = {
    [SYS_clone] = {"clone", 5, {VAL_ULONG, VAL_ULONG, VAL_PTR, VAL_PTR, VAL_ULONG}, VAL_INT},
    [SYS_brk] = {"brk", 1, {VAL_ULONG}, VAL_INT},
    [SYS_close] = {"close", 1, {VAL_UINT}, VAL_INT},
    [SYS_exit] = {"exit", 1, {VAL_INT}, VAL_NONE},
    [SYS_exit_group] = {"exit_group", 1, {VAL_INT}, VAL_NONE},
    [SYS_set_tid_address] = {"set_tid_address", 1, {VAL_PTR}, VAL_INT},
    [SYS_set_robust_list] = {"set_robust_list", 2, {VAL_PTR, VAL_SIZE_T}, VAL_LONG},
    [SYS_faccessat] = {"faccessat", 3, {VAL_INT, VAL_STR, VAL_INT}, VAL_INT},
    [SYS_kill] = {"kill", 2, {VAL_INT, VAL_INT}, VAL_INT},
    [SYS_listen] = {"listen", 2, {VAL_INT, VAL_INT}, VAL_INT},
    [SYS_munmap] = {"sys_munmap", 2, {VAL_PTR, VAL_SIZE_T}, VAL_INT}, //see first is ulong
    [SYS_openat] = {"openat", 4, {VAL_INT, VAL_STR, VAL_INT, VAL_INT}, VAL_INT}, //see umode_t
    [SYS_newfstatat] = {"newfstatat", 4, {VAL_INT, VAL_STR, VAL_PTR, VAL_INT}, VAL_INT},
    [SYS_fstat] = {"fstat", 2, {VAL_UINT, VAL_PTR}, VAL_INT},
    [SYS_accept] = {"accept", 3, {VAL_INT, VAL_PTR, VAL_PTR}, VAL_INT},
    [SYS_connect] = {"connect", 3, {VAL_INT, VAL_PTR, VAL_INT}, VAL_INT},
    [SYS_execve] = {"execve", 3, {VAL_STR, VAL_PTR, VAL_PTR}, VAL_INT},
    [SYS_ioctl] = {"ioctl", 3, {VAL_UINT, VAL_UINT, VAL_ULONG}, VAL_INT},
    [SYS_getrandom] = {"getrandom", 3, {VAL_PTR, VAL_SIZE_T, VAL_UINT}, VAL_SIZE_T},
    [SYS_lseek] = {"lseek", 3, {VAL_UINT, VAL_PTR, VAL_UINT}, VAL_INT}, //see off_t
    [SYS_ppoll] = {"ppoll", 5, {VAL_PTR, VAL_UINT, VAL_PTR, VAL_PTR, VAL_SIZE_T}, VAL_INT},
    [SYS_read] = {"read", 3, {VAL_UINT, VAL_PTR, VAL_SIZE_T}, VAL_SIZE_T},
    [SYS_write] = {"write", 3, {VAL_UINT, VAL_STR, VAL_SIZE_T}, VAL_SIZE_T}, //see how to copy string (it is not null terminated)
    [SYS_mprotect] = {"mprotect", 3, {VAL_ULONG, VAL_SIZE_T, VAL_ULONG}, VAL_INT},
    [SYS_socket] = {"socket", 3, {VAL_INT, VAL_INT, VAL_INT}, VAL_INT},
    [SYS_pread64] = {"pread64", 4, {VAL_UINT, VAL_PTR, VAL_SIZE_T, VAL_PTR}, VAL_SIZE_T},
    [SYS_prlimit64] = {"prlimit64", 4, {VAL_INT, VAL_UINT, VAL_PTR, VAL_PTR}, VAL_INT},
    [SYS_sendfile] = {"sendfile", 4, {VAL_INT, VAL_INT, VAL_PTR, VAL_SIZE_T}, VAL_SIZE_T},
    [SYS_socketpair] = {"socketpair", 4, {VAL_INT, VAL_INT, VAL_INT, VAL_PTR}, VAL_INT},
    [SYS_mmap] = {"mmap", 6, {VAL_PTR, VAL_PTR, VAL_PTR, VAL_PTR, VAL_PTR, VAL_PTR}, VAL_NONE},
    [SYS_recvfrom] = {"recvfrom", 6, {VAL_INT, VAL_PTR, VAL_SIZE_T, VAL_UINT, VAL_PTR, VAL_INT}, VAL_SIZE_T},
    [SYS_sendto] = {"sendto", 6, {VAL_INT, VAL_PTR, VAL_SIZE_T, VAL_UINT, VAL_PTR, VAL_INT}, VAL_SIZE_T},
};

#endif //CONTROLLER_H
