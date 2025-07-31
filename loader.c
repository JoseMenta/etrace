//
// Created by Jose Menta on 29/07/2025.
//
#include <bpf/libbpf.h>
#include "printer.h"
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


int exec_child(char** argv, const char* program) {
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

int load_ebpf(const pid_t pid) {
    const char* object_name = "controller.o";
    const char* map_name = "pid_hashmap";
    const char* enter_program_name = "detect_syscall_enter";
    const char* exit_program_name = "detect_syscall_exit";
    const char* syscall_info_buffer_name = "syscall_info_buffer";

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

    return bpf_object__find_map_fd_by_name(obj, syscall_info_buffer_name);
}

int main(int argc, char **argv) {

    if (argc < 2) {
        fatal_error("Usage: ./etrace <path_to_program>");
    }

    const char* program = argv[1];

    const pid_t pid = fork();
    if (pid == 0) {
        return exec_child(argv, program);
    }

    int status;

    const int rbFd = load_ebpf(pid);

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

