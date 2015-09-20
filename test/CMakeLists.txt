include_directories ( ../include ${CMAKE_CURRENT_SOURCE_DIR}/../../install/include)
add_definitions(-DCPPSSH_STATIC)
add_executable(cppsshtestalgos cppsshtestalgos.cpp cppsshtestutil.cpp)
add_executable(cppsshtestkeys cppsshtestkeys.cpp cppsshtestutil.cpp)
target_link_libraries(cppsshtestalgos cppssh)
target_link_libraries(cppsshtestkeys cppssh)
set_property(TARGET cppsshtestalgos PROPERTY CXX_STANDARD 11)
set_property(TARGET cppsshtestkeys PROPERTY CXX_STANDARD 11)
install(TARGETS cppsshtestalgos cppsshtestkeys DESTINATION bin)


