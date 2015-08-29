include_directories ( ../include ${CMAKE_CURRENT_SOURCE_DIR}/../../install/include)
add_definitions(-DCPPSSH_STATIC)
add_executable(cppsshexample cppsshexample.cpp)
target_link_libraries(cppsshexample cppssh)
set_property(TARGET cppsshexample PROPERTY CXX_STANDARD 11)
install(TARGETS cppsshexample DESTINATION bin)


