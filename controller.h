//
// Created by Jose Menta on 29/07/2025.
//

#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <sys/syscall.h>


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

#endif //CONTROLLER_H
