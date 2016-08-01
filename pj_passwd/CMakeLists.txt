cmake_minimum_required(VERSION 2.6)
project(pjpasswd)
add_executable(pjpasswd
	src/pj_passwd.cpp
	src/pj_getpass.c)

set(PJPASSWD_VERSION_MAJOR 0)
set(PJPASSWD_VERSION_MINOR 1)

configure_file("${PROJECT_SOURCE_DIR}/src/pj_config.h.in"
	"${PROJECT_SOURCE_DIR}/gen/pj_config_.h")

find_path(PJUTILS_INCLUDE_DIR pj_utils/delete.hpp
	PATHS
	${CMAKE_INSTALL_PREFIX}/include
	../pj_utils/include
	DOC "PJUTILS library")

if(${PJUTILS_INCLUDE_DIR} STREQUAL "PJUTILS_INCLUDE_DIR-NOTFOUND")
	message(FATAL_ERROR "Cannot find pjutils library (set PJUTILS_INCLUDE_DIR)")
endif()

include_directories(${PJUTILS_INCLUDE_DIR} ${PROJECT_SOURCE_DIR}/gen)

target_link_libraries(pjpasswd crypt pthread)

set(CMAKE_CXX_FLAGS "-std=c++11 -Wall ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_CXX_FLAGS_DEBUG "-g -D_DEBUG -O0")

install (TARGETS pjpasswd RUNTIME DESTINATION bin)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)
add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P cmake_uninstall.cmake
    COMMENT "Uninstalling ${PROJECT_NAME}")
