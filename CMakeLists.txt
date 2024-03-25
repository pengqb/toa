cmake_minimum_required(VERSION 3.15)
project(nf_toa C)

set(CMAKE_C_STANDARD 11)

#添加头文件搜索路径
INCLUDE_DIRECTORIES(/usr/src/kernels/4.19.90-2301.6.0.0186.0.231016.x86_64/include
        )

add_executable(nf_toa
        nf_toa/include/toa.h
        nf_toa/lb/client.c
        nf_toa/lb/nf_to_add.c
        nf_toa/server/server.c
        nf_toa/server/nf_toa.c)
