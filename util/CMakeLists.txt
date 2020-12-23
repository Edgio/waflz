# ------------------------------------------------------------------------------
# project setup
# ------------------------------------------------------------------------------
project(waflz)
cmake_minimum_required(VERSION 3.5)
# include source and test directories
# ------------------------------------------------------------------------------
# apps
# ------------------------------------------------------------------------------
include_directories(${CMAKE_SOURCE_DIR}/sub/is2)
add_subdirectory(wjc)
add_subdirectory(waflz_dump)
add_subdirectory(waflz_server)
# ----------------------------------------------------------
# only build scopez server if RATE_LIMITING enabled
# ----------------------------------------------------------
if (BUILD_RATE_LIMITING)
add_subdirectory(scopez_server)
endif()
#add_subdirectory(wpc)
