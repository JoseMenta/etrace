cmake_minimum_required(VERSION 3.28.3)
project(etrace C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_program(CLANG_EXECUTABLE clang REQUIRED)

# Paths
set(BPF_SOURCE ${CMAKE_SOURCE_DIR}/controller.c)
set(BPF_OBJECT ${CMAKE_BINARY_DIR}/controller.o)

add_custom_command(
        OUTPUT ${BPF_OBJECT}
        COMMAND ${CLANG_EXECUTABLE}
        -target bpf
        -D__TARGET_ARCH_arm
        -O2 -g
        -c ${BPF_SOURCE}
        -o ${BPF_OBJECT}
        DEPENDS ${BPF_SOURCE}
        COMMENT "Compiling BPF program ${BPF_SOURCE}"
)

add_custom_target(bpf_objects ALL DEPENDS ${BPF_OBJECT})

add_executable(etrace loader.c
        printer.c)

target_compile_options(etrace PRIVATE -O2 -g -Wall)

# Link to libbpf if needed (remove if not using)
find_library(LIBBPF_LIBRARY bpf REQUIRED)
target_link_libraries(etrace ${LIBBPF_LIBRARY})

# Ensure the BPF object is built before userspace
add_dependencies(etrace bpf_objects)

add_custom_command(TARGET etrace POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${BPF_OBJECT} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/controller.o
        COMMENT "Copying controller.o to runtime directory"
)

add_executable(test test.c)
