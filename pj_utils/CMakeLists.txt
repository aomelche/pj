cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(pjutils VERSION 0.1 LANGUAGES CXX)
add_library(pjutils INTERFACE)

target_include_directories(pjutils INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include/ DESTINATION include)

export(TARGETS pjutils FILE pjutils.cmake)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)
add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P cmake_uninstall.cmake
    COMMENT "Uninstalling ${PROJECT_NAME}")
