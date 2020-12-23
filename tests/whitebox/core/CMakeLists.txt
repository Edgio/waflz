# ------------------------------------------------------------------------------
# project setup
# ------------------------------------------------------------------------------
project(waflz_core_tests)
cmake_minimum_required(VERSION 3.5)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_BINARY_DIR}
  ${CMAKE_BINARY_DIR}/proto
)

add_waflz_wb_test(instances)
add_waflz_wb_test(matched_data)
add_waflz_wb_test(acl)
add_waflz_wb_test(acl_accesslist)
add_waflz_wb_test(challenge)
add_waflz_wb_test(profile_policies)
add_waflz_wb_test(shell_shock)
add_waflz_wb_test(decode)
add_waflz_wb_test(op)
add_waflz_wb_test(var)
add_waflz_wb_test(tx)
add_waflz_wb_test(render)
add_waflz_wb_test(scopes)
