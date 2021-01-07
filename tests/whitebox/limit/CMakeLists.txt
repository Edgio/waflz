# ------------------------------------------------------------------------------
# Project setup
# ------------------------------------------------------------------------------
project(waflz_limit_tests)
cmake_minimum_required(VERSION 3.5)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_BINARY_DIR}
  ${CMAKE_BINARY_DIR}/proto
)
# ------------------------------------------------------------------------------
# seem to require this for lzo linking
# ------------------------------------------------------------------------------
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -no-pie")
add_waflz_wb_test(rl_op)
add_waflz_wb_test(enforcer)
add_waflz_wb_test(config)
add_waflz_wb_test(integration)
