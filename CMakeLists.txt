cmake_minimum_required(VERSION 3.19)
project(untitled)

set(CMAKE_CXX_STANDARD 14)

find_package(OpenSSL REQUIRED)

add_executable(untitled main.cpp)

target_link_libraries(${PROJECT_NAME} crypto ssl)