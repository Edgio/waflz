# ------------------------------------------------------------------------------
# project setup
# ------------------------------------------------------------------------------
project(waflz)
cmake_minimum_required(VERSION 3.5)
include_directories(
  /usr/include/libxml2
 )
add_waflz_wb_test(parser_json)
add_waflz_wb_test(parser_xml)
