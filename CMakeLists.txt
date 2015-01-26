cmake_minimum_required(VERSION 2.8)
project(rxStats)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    include_directories("/usr/include/x86_64-linux-gnu/")
    link_directories("/usr/lib/x86_64-linux-gnu/")
endif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/binaries)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/libraries)

add_definitions("-std=c++11 -g -O3 -march=native -Wall -Wextra")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

file(GLOB_RECURSE sourceFiles src/*.cpp)
add_executable(${CMAKE_PROJECT_NAME} ${sourceFiles})

find_package(NL REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} ${LIBNL_LIBRARIES})
add_definitions(${CGAL_DEFINITIONS})
include_directories(${LIBNL_INCLUDE_DIR})