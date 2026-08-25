cmake_minimum_required(VERSION 3.14)

find_package(PkgConfig REQUIRED)

# Dependencies inherited from parent CMakeLists.txt:
#   SYSTEMD_LIBRARIES, SYSTEMD_INCLUDE_DIRS  (libsystemd)
#   SDBUSPLUSPLUS_LIBRARIES, SDBUSPLUSPLUS_INCLUDE_DIRS (sdbusplus)
# Re-query in case subdirectory is evaluated independently.
pkg_check_modules(SYSTEMD libsystemd REQUIRED)
pkg_check_modules(SDBUSPLUSPLUS sdbusplus REQUIRED)

# mail_alert_manager.cpp sources (exclude _main.cpp which has main() and D-Bus
# application setup that requires a live D-Bus session).
set(MAIL_ALERT_SRC ${CMAKE_SOURCE_DIR}/src/mail_alert_manager.cpp)

add_executable(test_mail_alert_manager
    test_main.cpp
    test_mail_alert_manager.cpp
    stubs/smtp_stubs.cpp
    ${MAIL_ALERT_SRC}
)

# stubs/ MUST appear before all other include directories so that
# <libesmtp.h> and <auth-client.h> resolve to the stub headers
# (libesmtp is not installed in the Docker build environment).
target_include_directories(test_mail_alert_manager
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/stubs
        ${CMAKE_SOURCE_DIR}/include
        ${SDBUSPLUSPLUS_INCLUDE_DIRS}
        ${SYSTEMD_INCLUDE_DIRS}
)

target_link_libraries(test_mail_alert_manager
    PRIVATE
        GTest::gtest
        GTest::gmock
        ${SDBUSPLUSPLUS_LIBRARIES}
        ${SYSTEMD_LIBRARIES}
        ssl
)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(test_mail_alert_manager
    PROPERTIES TIMEOUT 60
)
