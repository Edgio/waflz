# ----------------------------------------------------------------------------
# Copyright (C) 2014 Verizon.  All Rights Reserved.
# All Rights Reserved
#
#   Author: Reed P Morrison
#   Date:   09/30/2015  
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# ------------------------------------------------------------------------------
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
add_waflz_wb_test(profile_policies)
add_waflz_wb_test(shell_shock)
add_waflz_wb_test(decode)
add_waflz_wb_test(op)
add_waflz_wb_test(var)
add_waflz_wb_test(tx)
add_waflz_wb_test(render)
add_waflz_wb_test(scopes)
