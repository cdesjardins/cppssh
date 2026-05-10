cmake_minimum_required(VERSION 3.5)
project(cppssh CXX)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/../include")
include(compilerflags)
set(CMAKE_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/../install")
set(BOTAN_BASE_DIR "${CMAKE_SOURCE_DIR}/../botan/install")

find_path(HAVE_BOTAN "botan-3" PATHS "${BOTAN_BASE_DIR}/include/")
if (NOT HAVE_BOTAN)
    MESSAGE(FATAL_ERROR "Need to run the makebotan.py script, could not find Botan includes")
endif()
set(HAVE_BOTAN "${HAVE_BOTAN}/botan-3")

find_library(HAVE_BOTAN_DBG_LIB NAMES botand botan botan-3 PATHS "${BOTAN_BASE_DIR}/lib/botan" "${BOTAN_BASE_DIR}/lib/botan/debug")
find_library(HAVE_BOTAN_LIB NAMES botan botan-3 PATHS "${BOTAN_BASE_DIR}/lib/botan" "${BOTAN_BASE_DIR}/lib/botan/release")
if ((NOT HAVE_BOTAN_LIB) OR (NOT HAVE_BOTAN_DBG_LIB))
    MESSAGE(FATAL_ERROR "Need to run the makebotan.py script, could not find Botan library")
endif()

find_library(HAVE_CDLOGGER_DBG_LIB NAMES CDLoggerd PATHS "${CMAKE_INSTALL_PREFIX}/lib")
find_library(HAVE_CDLOGGER_LIB NAMES CDLogger PATHS "${CMAKE_INSTALL_PREFIX}/lib")
if ((NOT HAVE_CDLOGGER_LIB) AND (NOT HAVE_CDLOGGER_DBG_LIB))
    MESSAGE(FATAL_ERROR "Could not find CDLogger library")
endif()

# Wrap the external static libraries as IMPORTED targets. This is the
# CMake-blessed way to express per-configuration external libraries; it
# survives transitive propagation through INTERFACE_LINK_LIBRARIES on every
# generator (Ninja, Visual Studio, Xcode), which raw paths in generator
# expressions don't always do under multi-config generators.
add_library(cppssh::botan STATIC IMPORTED GLOBAL)
set_target_properties(cppssh::botan PROPERTIES
    IMPORTED_CONFIGURATIONS "RELEASE;DEBUG"
    IMPORTED_LOCATION_RELEASE        "${HAVE_BOTAN_LIB}"
    IMPORTED_LOCATION_RELWITHDEBINFO "${HAVE_BOTAN_LIB}"
    IMPORTED_LOCATION_MINSIZEREL     "${HAVE_BOTAN_LIB}"
    IMPORTED_LOCATION_DEBUG          "${HAVE_BOTAN_DBG_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES    "${HAVE_BOTAN}"
)

if (HAVE_CDLOGGER_LIB OR HAVE_CDLOGGER_DBG_LIB)
    add_library(cppssh::cdlogger STATIC IMPORTED GLOBAL)
    set(_cdlogger_release "${HAVE_CDLOGGER_LIB}")
    set(_cdlogger_debug   "${HAVE_CDLOGGER_DBG_LIB}")
    if (NOT _cdlogger_release)
        set(_cdlogger_release "${HAVE_CDLOGGER_DBG_LIB}")
    endif()
    if (NOT _cdlogger_debug)
        set(_cdlogger_debug "${HAVE_CDLOGGER_LIB}")
    endif()
    set_target_properties(cppssh::cdlogger PROPERTIES
        IMPORTED_CONFIGURATIONS "RELEASE;DEBUG"
        IMPORTED_LOCATION_RELEASE        "${_cdlogger_release}"
        IMPORTED_LOCATION_RELWITHDEBINFO "${_cdlogger_release}"
        IMPORTED_LOCATION_MINSIZEREL     "${_cdlogger_release}"
        IMPORTED_LOCATION_DEBUG          "${_cdlogger_debug}"
    )
endif()

file(GLOB cppssh_INCLUDES "include/*.h")
install(FILES ${cppssh_INCLUDES} DESTINATION include/cppssh/)

add_subdirectory (src)
add_subdirectory (examples)
add_subdirectory (test)
########### install files ###############

