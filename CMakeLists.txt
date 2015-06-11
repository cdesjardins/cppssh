cmake_minimum_required(VERSION 3.1)
project(cppssh CXX)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/../include")
include(compilerflags)
set(CMAKE_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/../install")
# undo warning level 4 because it makes too much noise from botan :(
#string(REGEX REPLACE "/W4" "/W3" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

find_file(HAVE_BOTAN "botan/botan.h" PATHS "${CMAKE_INSTALL_PREFIX}/include" "${CMAKE_INSTALL_PREFIX}/include/botan-1.11/")
if (NOT HAVE_BOTAN)
    MESSAGE(FATAL_ERROR "Could not find Botan includes ${CMAKE_INSTALL_PREFIX}")
endif()
string(FIND ${HAVE_BOTAN} "botan/botan.h" BOTAN_STR)
string(SUBSTRING ${HAVE_BOTAN} 0 ${BOTAN_STR} HAVE_BOTAN)

find_library(HAVE_BOTAN_DBG_LIB NAMES botan-111 PATHS "${CMAKE_INSTALL_PREFIX}/lib/Debug")
find_library(HAVE_BOTAN_LIB NAMES botan-111 PATHS "${CMAKE_INSTALL_PREFIX}/lib")
if ((NOT HAVE_BOTAN_LIB) OR (NOT HAVE_BOTAN_DBG_LIB))
    MESSAGE(FATAL_ERROR "Could not find Botan library")
endif()

find_library(HAVE_CDLOGGER_DBG_LIB NAMES CDLoggerd PATHS "${CMAKE_INSTALL_PREFIX}/lib")
find_library(HAVE_CDLOGGER_LIB NAMES CDLogger PATHS "${CMAKE_INSTALL_PREFIX}/lib")
if ((NOT HAVE_CDLOGGER_LIB) OR (NOT HAVE_CDLOGGER_DBG_LIB))
    MESSAGE(FATAL_ERROR "Could not find CDLogger library")
endif()

file(GLOB cppssh_INCLUDES "include/*.h")
install(FILES ${cppssh_INCLUDES} DESTINATION include/cppssh/)

add_subdirectory (src)
add_subdirectory (examples)
########### install files ###############

