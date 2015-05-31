include_directories ( ../include ${CMAKE_CURRENT_SOURCE_DIR}/../../install/include)
add_definitions(-DCPPSSH_STATIC)
add_executable(cppsshtest cppsshtest.cpp)
target_link_libraries(cppsshtest cppssh)
set_property(TARGET cppsshtest PROPERTY CXX_STANDARD 11)
install(TARGETS cppsshtest DESTINATION bin)


