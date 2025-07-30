cmake_minimum_required(VERSION 3.28.3)
project(etrace C)

set(CMAKE_C_STANDARD 11)

add_executable(etrace
        loader.c
        controller.c)
