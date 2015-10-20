cmake_minimum_required(VERSION 3.1)
project(cppssh CXX)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/../include")
set(CMAKE_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/../install")
include(compilerflags)
include(cppsshpackages)

file(GLOB cppssh_INCLUDES "include/*.h")
install(FILES ${cppssh_INCLUDES} DESTINATION include/cppssh/)

add_subdirectory (src)
add_subdirectory (examples)
add_subdirectory (test)
########### install files ###############

