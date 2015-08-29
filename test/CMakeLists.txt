include_directories ( ../include ${CMAKE_CURRENT_SOURCE_DIR}/../../install/include)
add_definitions(-DCPPSSH_STATIC)
add_executable(cppsshtestalgos cppsshtestalgos.cpp)
target_link_libraries(cppsshtestalgos cppssh)
set_property(TARGET cppsshtestalgos PROPERTY CXX_STANDARD 11)
install(TARGETS cppsshtestalgos DESTINATION bin)


