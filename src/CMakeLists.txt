set(cppssh_LIB_SRCS

include_directories ( ${HAVE_BOTAN} )

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

add_definitions(-DNE7SSH_EXPORTS -DNE7SSH_FULL_VERSION="${FULL_VERSION}" -DNE7SSH_SHORT_VERSION="${SHORT_VERSION}")
add_library(ne7ssh STATIC ${net7ssh_LIB_SRCS})

set_property(TARGET ne7ssh PROPERTY CXX_STANDARD 11)
#set_property(TARGET ne7ssh PROPERTY CXX_STANDARD_REQUIRED ON)
#add_library(net7ssh SHARED ${net7ssh_LIB_SRCS})
#target_link_libraries(net7ssh ${HAVE_BOTAN_LIB})
if(MSVC)
#    target_link_libraries(net7ssh ws2_32)
    target_link_libraries(ne7ssh ws2_32)
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_CLANGXX OR CMAKE_COMPILER_IS_CLANGCC)
    target_link_libraries(ne7ssh rt)
endif()

#install(TARGETS net7ssh  DESTINATION lib)
install(TARGETS ne7ssh  DESTINATION lib)
install(FILES ne7ssh.h ne7ssh_types.h ne7ssh_error.h DESTINATION include)

