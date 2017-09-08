project(${OPENSSLPP_TEST_PROJECT})

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

include_directories(${OPENSSLPP_INCLUDE})

set(SOURCES
    test_dsa.cpp
    test_rsa.cpp
    main.cpp)

add_executable(${OPENSSLPP_TEST_PROJECT} ${SOURCES})

target_link_libraries(${OPENSSLPP_TEST_PROJECT} ${GTEST_BOTH_LIBRARIES} ${OPENSSLPP_ADDITIONAL_LIBS} opensslpp)
