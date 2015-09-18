cmake_minimum_required(VERSION 3.1)
project(cppssh CXX)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/../include")
include(compilerflags)
set(CMAKE_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/../install")
set(BOTAN_BASE_DIR "${CMAKE_SOURCE_DIR}/../botan/install")

find_file(HAVE_BOTAN "botan/botan.h" PATHS "${BOTAN_BASE_DIR}/include/botan-1.11/")
if (NOT HAVE_BOTAN)
    MESSAGE(FATAL_ERROR "Need to run the makebotan.py script, could not find Botan includes")
endif()
string(FIND ${HAVE_BOTAN} "botan/botan.h" BOTAN_STR)
string(SUBSTRING ${HAVE_BOTAN} 0 ${BOTAN_STR} HAVE_BOTAN)

find_library(HAVE_BOTAN_DBG_LIB NAMES botan botan-1.11 PATHS "${BOTAN_BASE_DIR}/lib/botan/debug")
find_library(HAVE_BOTAN_LIB NAMES botan botan-1.11 PATHS "${BOTAN_BASE_DIR}/lib/botan/release")
if ((NOT HAVE_BOTAN_LIB) OR (NOT HAVE_BOTAN_DBG_LIB))
    MESSAGE(FATAL_ERROR "Need to run the makebotan.py script, could not find Botan library")
endif()

find_library(HAVE_CDLOGGER_DBG_LIB NAMES CDLoggerd PATHS "${CMAKE_INSTALL_PREFIX}/lib")
find_library(HAVE_CDLOGGER_LIB NAMES CDLogger PATHS "${CMAKE_INSTALL_PREFIX}/lib")
if ((NOT HAVE_CDLOGGER_LIB) AND (NOT HAVE_CDLOGGER_DBG_LIB))
    MESSAGE(FATAL_ERROR "Could not find CDLogger library")
endif()

file(GLOB cppssh_INCLUDES "include/*.h")
install(FILES ${cppssh_INCLUDES} DESTINATION include/cppssh/)

add_subdirectory (src)
add_subdirectory (examples)
add_subdirectory (test)
########### install files ###############

