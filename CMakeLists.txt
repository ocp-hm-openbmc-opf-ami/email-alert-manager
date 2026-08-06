cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(mail-alert-manager CXX)
set(CMAKE_CXX_STANDARD 23)
option(TESTS "Build Unit Test" OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
add_definitions(-DBOOST_ERROR_CODE_HEADER_ONLY)
add_definitions(-DBOOST_SYSTEM_NO_DEPRECATED)
add_definitions(-DBOOST_ALL_NO_LIB)
add_definitions(-DBOOST_NO_RTTI)
add_definitions(-DBOOST_NO_TYPEID)
add_definitions(-DBOOST_ASIO_DISABLE_THREADS)

set(SRC_FILES src/mail_alert_manager_main.cpp src/mail_alert_manager.cpp)

# import libsystemd
find_package(PkgConfig REQUIRED)
pkg_check_modules(SYSTEMD libsystemd REQUIRED)

find_package(OpenSSL REQUIRED)
pkg_check_modules(CRYPT libcrypto REQUIRED)

# import sdbusplus
find_package(PkgConfig REQUIRED)
pkg_check_modules(SDBUSPLUSPLUS sdbusplus REQUIRED)
pkg_get_variable(SYSTEMD_SYSTEM_UNIT_DIR systemd systemdsystemunitdir)

add_executable(mail-alert-manager ${SRC_FILES})

target_link_libraries(mail-alert-manager systemd)
target_link_libraries(mail-alert-manager boost_coroutine)
target_link_libraries(mail-alert-manager sdbusplus -lstdc++fs)
target_link_libraries(mail-alert-manager esmtp)
target_link_libraries(mail-alert-manager ssl)
target_link_libraries(mail-alert-manager ${Boost_LIBRARIES})
target_link_libraries(mail-alert-manager OpenSSL::Crypto  OpenSSL::SSL)
link_directories(${EXTERNAL_INSTALL_LOCATION}/lib)

set(SERVICE_FILES
    ${PROJECT_SOURCE_DIR}/service_files/mail-alert-manager.service)

install(FILES ${SERVICE_FILES} DESTINATION ${SYSTEMD_SYSTEM_UNIT_DIR})
install(TARGETS mail-alert-manager DESTINATION bin)

if(TESTS)
    # Make stub headers available so the production binary compiles without libesmtp-dev
    target_include_directories(mail-alert-manager PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/stubs)
    # Provide a stub libesmtp so the production binary links without the real library
    add_library(esmtp STATIC tests/stubs/smtp_stubs.cpp)
    target_include_directories(esmtp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests/stubs)
    # GoogleTest — prefer system installation; fall back to FetchContent
    find_package(GTest QUIET)
    if(NOT GTest_FOUND)
        include(FetchContent)
        FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG        v1.14.0
        )
        FetchContent_MakeAvailable(googletest)
    endif()
    enable_testing()
    add_subdirectory(tests)
endif()

