include_directories ( ../include ${HAVE_BOTAN} )
add_definitions(-DCPPSSH_STATIC)
add_executable(cppsshtest cppsshtest.cpp)
target_link_libraries(cppsshtest cppssh ${HAVE_BOTAN_LIB})
set_property(TARGET cppsshtest PROPERTY CXX_STANDARD 11)
install(TARGETS cppsshtest DESTINATION bin)


