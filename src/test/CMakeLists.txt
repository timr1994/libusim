cmake_minimum_required(VERSION 3.10)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_BUILD_TYPE Debug)
add_executable(testuiim rand_help test)
set_property(TARGET testuiim PROPERTY C_STANDARD 99)


#Check for pthread lib
unset(PTHREADFOUND CACHE)
find_library(PTHREADFOUND pthread)
if(NOT PTHREADFOUND)
    message(STATUS "PTHREAD NOT FOUND")
    target_link_libraries(testuiim uiim qcbor mbedcrypto m)
else()
    message(STATUS "PTHREAD FOUND ${PTHREADFOUND}")
    target_link_libraries(testuiim uiim qcbor mbedcrypto pthread m)
endif()
configure_file(test.h.in ${CMAKE_CURRENT_SOURCE_DIR}/test.h)




