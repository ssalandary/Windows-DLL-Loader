cmake_minimum_required(VERSION 3.27)
project(LoadLibrary C)

set(CMAKE_C_STANDARD 11)
set(SOURCES
        loadlibrary.c
        main.c
 "Utils/logging.c")
set(HEADERS
        loadlibrary.h
 "Utils/logging.h")
add_executable(LoadLibrary ${SOURCES} ${HEADERS})