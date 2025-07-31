//
// Created by Jose Menta on 29/07/2025.
//
#include <bpf/libbpf.h>
#include "controller.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ctype.h>

extern char **environ; // Use parent's environment

void fatal_error(const char *msg) {
    puts(msg);
    exit(1);
}

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

static int log_syscall(void* ctx, void* data, size_t len) {

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

int main(int argc, char **argv) {
    int status;
    const char* object_name = "controller.o";
    const char* map_name = "pid_hashmap";
    const char* enter_program_name = "detect_syscall_enter";
    const char* exit_program_name = "detect_syscall_exit";
    const char* syscall_info_buffer_name = "syscall_info_buffer";


    if (argc < 2) {
        fatal_error("Usage: ./etrace <path_to_program>");
    }

    const char* program = argv[1];

    const pid_t pid = fork();
    if (pid == 0) {
        //Child
        int fd = open("/dev/null", O_WRONLY);
        if (fd == -1) {
            fatal_error("Could not open /dev/null");
        }
        dup2(fd, STDOUT_FILENO);
        sleep(1); //Wait for parent tracer

        execve(program, &argv[1], environ);
        //If execve failed, return error
        return 1;
    }

    printf("Spawned child process with a PID of %d\n", pid);
    struct bpf_object* obj = bpf_object__open(object_name);
    if (!obj) {
        fatal_error("failed to open the BPF object");
    }

    //Load the object into the kernel
    if (bpf_object__load(obj)) {
        fatal_error("failed to load the BPF object into the kernel");
    }

    struct bpf_program* enter_program = bpf_object__find_program_by_name(obj, enter_program_name);
    struct bpf_program* exit_program = bpf_object__find_program_by_name(obj, exit_program_name);


    if (!enter_program || !exit_program) {
        fatal_error("failed to find the BPF program");
    }

    //Attach the program to the tracepoint
    if (!bpf_program__attach(enter_program) || !bpf_program__attach(exit_program)) {
        fatal_error("failed to attach the BPF program");
    }

    struct bpf_map* syscall_map = bpf_object__find_map_by_name(obj, map_name);
    if (!syscall_map) {
        fatal_error("failed to find the BPF map");
    }

    const char* key = "child_pid";
    const int err = bpf_map__update_elem(syscall_map, key, strlen(key) + 1, (void*)& pid, sizeof(pid), 0);
    if (err) {
        printf("Error is %d", err);
        fatal_error("failed to insert child_pid in pid hashmap");
    }

    const int rbFd = bpf_object__find_map_fd_by_name(obj, syscall_info_buffer_name);

    //Pass the function to process the incoming data in the buffer
    struct ring_buffer* rBuffer = ring_buffer__new(rbFd, log_syscall, NULL, NULL);

    if (!rBuffer) {
        fatal_error("failed to create ring buffer");
    }

    if (wait(&status) == -1) {
        fatal_error("failed to wait for child process");
    }

    while (1) {
        //returns the number of records consumed across all registered ring buffers
        const int e = ring_buffer__consume(rBuffer);
        if (!e) {
            break;
        }
        sleep(1);
    }
    printf("\n");
    return 0;
}

