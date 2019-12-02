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
project(waflz)
cmake_minimum_required(VERSION 2.8.0)
# ------------------------------------------------------------------------------
# wb_ac
# ------------------------------------------------------------------------------
SET(SRCS wb_parser_json.cc)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
add_executable(wb_parser_json ${HDRS} ${SRCS})
add_dependencies(wb_parser_json waflzcore)
target_link_libraries(wb_parser_json ${DEBUG_LIBRARIES} compiled_catch waflzcore ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_parser_json PROPERTIES OUTPUT_NAME "wb_parser_json")
add_test(parser_json wb_parser_json)
