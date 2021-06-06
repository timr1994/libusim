cmake_minimum_required(VERSION 3.10)

#Check for mbedcrypto lib
unset(MBEDCRYPTO CACHE)
find_library(MBEDCRYPTO mbedcrypto)
if(NOT MBEDCRYPTO)
    message(SEND_ERROR "MBEDCRYPTO NOT FOUND")
else()
    message(STATUS "MBEDCRYPTO FOUND ${MBEDCRYPTO}")
endif()

add_library(uiim SHARED uiim hash_message hash_message_cbor cbor_help help_functions)
set_property(TARGET uiim PROPERTY C_STANDARD 99)
target_link_libraries(uiim mbedcrypto pthread)
set_target_properties(uiim PROPERTIES
  VERSION 1.0.0
  # "compatibility version" in semantic format in Mach-O binary file
  SOVERSION 1.0.0
  PUBLIC_HEADER "uiim.h;hash_message.h;hash_message_cbor.h;cbor_help.h;help_functions.h"
)
install(TARGETS uiim
        LIBRARY
          DESTINATION lib
          COMPONENT Libraries
          NAMELINK_COMPONENT Development
        PUBLIC_HEADER
          DESTINATION include
          COMPONENT Development
       )

if(TESTUIIM)
add_subdirectory(test ../bin)
endif()
