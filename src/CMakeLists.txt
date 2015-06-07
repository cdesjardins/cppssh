file(GLOB cppssh_LIB_SRCS
    ${SRCS}
    "*.h"
    "*.cpp"
    "../include/*.h"
)

include_directories (${HAVE_BOTAN} ${CMAKE_CURRENT_SOURCE_DIR}/../include ${CMAKE_CURRENT_SOURCE_DIR}/../../install/include ${CMAKE_CURRENT_SOURCE_DIR}/../../include)

find_file(HAVE_GIT git)
if (HAVE_GIT)
    exec_program(
        "git"
        ${CMAKE_CURRENT_SOURCE_DIR}
        ARGS "describe --dirty --always"
        OUTPUT_VARIABLE FULL_VERSION )
    string(FIND ${FULL_VERSION} "-" index)
    string(SUBSTRING ${FULL_VERSION} 0 ${index} SHORT_VERSION)
else()
    set(FULL_VERSION "0.x")
    set(SHORT_VERSION "0.x")
endif()
message(STATUS "Using version numbers: ${FULL_VERSION} and ${SHORT_VERSION}")

add_definitions(-DCPPSSH_EXPORTS -DCPPSSH_FULL_VERSION="${FULL_VERSION}" -DCPPSSH_SHORT_VERSION="${SHORT_VERSION}")
add_library(cppssh STATIC ${cppssh_LIB_SRCS})
if(MSVC)
    target_link_libraries(cppssh ws2_32)
endif()
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    target_link_libraries(cppssh rt)
endif()
target_link_libraries(cppssh CDLogger optimized ${HAVE_BOTAN_LIB} debug ${HAVE_BOTAN_DBG_LIB})

include(deffilename)
define_file_basename_for_sources(cppssh)
set_property(TARGET cppssh PROPERTY CXX_STANDARD 11)
install(TARGETS cppssh DESTINATION lib)

