# ------------------------------------------------------------------------------
# Project setup
# ------------------------------------------------------------------------------
project(waflz_db_tests)
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

add_waflz_wb_test(kycb_db)
add_waflz_wb_test(lm_db)
# commenting out -requires redis to run...
#add_waflz_wb_test(redis_db)
