cmake_minimum_required(VERSION 3.4)

project(opensslpp)

set(CMAKE_CXX_STANDARD 14)

if(MSVC)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
    set(OPENSSLPP_ADDITIONAL_LIBS Ws2_32 crypt32)
endif()

get_filename_component(OPENSSLPP_ROOT "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)

set(OPENSSLPP_INCLUDE "${OPENSSLPP_ROOT}/include")
include_directories(${OPENSSLPP_INCLUDE})

set(OPENSSL_MSVC_STATIC_RT ON)
set(OPENSSL_USE_STATIC_LIBS ON)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(Threads)

set(OPENSSLPP_HEADERS "${OPENSSLPP_INCLUDE}/opensslpp")

set(HEADERS
    ${OPENSSLPP_HEADERS}/aes.h
    ${OPENSSLPP_HEADERS}/rsa.h
    ${OPENSSLPP_HEADERS}/sha.h

    ${OPENSSLPP_HEADERS}/base64.h
    ${OPENSSLPP_HEADERS}/random.h

    ${OPENSSLPP_HEADERS}/details/common.h
    )

add_library(${PROJECT_NAME} STATIC ${HEADERS})
set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE CXX)

set(OPENSSLPP_TEST_PROJECT test_${PROJECT_NAME})

add_test(NAME ${OPENSSLPP_TEST_PROJECT} COMMAND ${OPENSSLPP_TEST_PROJECT})

add_subdirectory(tests)

enable_testing()
