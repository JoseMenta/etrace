//
// Created by Jose Menta on 31/07/2025.
//

#include "printer.h"
#include "controller.h"
#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>


bool initialized = false;

static void print_escaped(const char* str) {
    putchar('\"');
    for (; *str; str++) {
        switch (*str) {
        case '\n': printf("\\n"); break;
        case '\t': printf("\\t"); break;
        case '\r': printf("\\r"); break;
        case '\b': printf("\\b"); break;
        case '\f': printf("\\f"); break;
        case '\\': printf("\\\\"); break;
        case '\"': printf("\\\""); break;
        case '\a': printf("\\a"); break;
        case '\v': printf("\\v"); break;
        default:
            if (!isprint(*str)) {
                // Print non-printable characters as \xHH
                printf("\\x%02x", (unsigned char)*str);
            } else {
                putchar(*str);
            }
        }
    }
    putchar('\"');
    putchar(',');
}

static void print_arg(arg_val* val) {
    switch (val->type) {
    case VAL_SIZE_T:
        printf("%lu,", val->size_t_val);
        break;
    case VAL_LONG:
        printf("%ld,", val->long_val);
        break;
    case VAL_INT:
        printf("%d,", val->int_val);
        break;
    case VAL_STR:
        print_escaped(val->str_val);
        break;
    case VAL_UINT:
        printf("%u,", val->uint_val);
        break;
    case VAL_ULONG:
        printf("%lu,", val->ulong_val);
        break;
    default:
        if (val->ptr_val == NULL) {
            printf("NULL,");
        }else {
            printf("%p,", val->ptr_val);
        }
    }
}

static void print_ret(const long val, const long syscall_num) {
    switch (syscalls[syscall_num].ret_type) {
    case VAL_PTR:
        printf("%p\n", (void*) val);
        break;
    default:
        printf("%lu\n", val);
    }
}

int log_syscall(void* ctx, void* data, size_t len) {

    inner_syscall_info* info = data;
    if (!info) {
        return -1;
    }

    if (info->mode == SYS_ENTER) {
        initialized = true;
        printf("%s(", info->name);

        for (int i = 0; i < info->num_args; i++) {
            print_arg(&info->args[i]);
        }
        printf("\b) = ");
    }else if (info->mode == SYS_EXIT && initialized){
        //Print hex return value
        print_ret(info->ret_val, info->syscall_num);
    }

    return 0;
}