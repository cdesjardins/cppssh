file(GLOB cppssh_LIB_SRCS
    ${SRCS}
    "*.h"
    "*.cpp"
    "../include/*.h"
)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    file(GLOB platform_LIB_SRCS
        "win/*.h"
        "win/*.cpp")
else()
    file(GLOB platform_LIB_SRCS
        "posix/*.h"
        "posix/*.cpp")
endif()


include_directories (${HAVE_BOTAN} ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../include ${CMAKE_CURRENT_SOURCE_DIR}/../../install/include ${CMAKE_CURRENT_SOURCE_DIR}/../../include)

find_file(HAVE_GIT git)
if (HAVE_GIT)
    execute_process(
        COMMAND git describe --dirty --always
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE FULL_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(FIND ${FULL_VERSION} "-" index)
    string(SUBSTRING ${FULL_VERSION} 0 ${index} SHORT_VERSION)
else()
    set(FULL_VERSION "0.x")
    set(SHORT_VERSION "0.x")
endif()
message(STATUS "Using version numbers: ${FULL_VERSION} and ${SHORT_VERSION}")

add_definitions(-DCPPSSH_EXPORTS -DCPPSSH_FULL_VERSION="${FULL_VERSION}" -DCPPSSH_SHORT_VERSION="${SHORT_VERSION}")
add_library(cppssh STATIC ${cppssh_LIB_SRCS} ${platform_LIB_SRCS})
if(MSVC)
    target_link_libraries(cppssh PRIVATE ws2_32)
endif()
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    target_link_libraries(cppssh PRIVATE rt pthread)
endif()

# Botan and CDLogger are referenced by cppssh's public API (headers expose
# their types in some places), so consumers of cppssh must link them too.
# We use IMPORTED targets defined in the parent CMakeLists; they carry
# per-config IMPORTED_LOCATION_* and propagate cleanly through
# INTERFACE_LINK_LIBRARIES on every generator, including multi-config ones
# where raw library paths inside generator expressions can fail to survive
# transitive propagation.
target_link_libraries(cppssh PUBLIC cppssh::botan)
if (TARGET cppssh::cdlogger)
    target_link_libraries(cppssh PUBLIC cppssh::cdlogger)
endif()

include(deffilename)
define_file_basename_for_sources(cppssh)
set_property(TARGET cppssh PROPERTY CXX_STANDARD 20)
install(TARGETS cppssh DESTINATION lib)

