cmake_minimum_required(VERSION 3.29)
project(ex1 C)

set(CMAKE_C_STANDARD 23)

add_executable(ex1 server.c client.c LinkedList.c)
