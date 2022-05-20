cmake_minimum_required(VERSION 3.23)
project(Ec2b)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(Ec2b
        aes.c
        magic.h
        main.cpp
        util.c
        util.h
        )
