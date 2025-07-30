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

extern char **environ; // Use parent's environment




void fatal_error(const char *msg) {
    puts(msg);
    exit(1);
}

int main(int argc, char **argv) {
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
        sleep(2); //Wait for parent tracer

        execve(program, &argv[1], environ);
    } else {
        //Tracer
    }
}

