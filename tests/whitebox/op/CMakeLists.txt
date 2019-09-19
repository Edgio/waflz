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
# wb_nms
# ------------------------------------------------------------------------------
SET(SRCS wb_nms.cc)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
add_executable(wb_nms ${HDRS} ${SRCS})
add_dependencies(wb_nms waflzcore)
target_link_libraries(wb_nms ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_nms PROPERTIES OUTPUT_NAME "wb_nms")
add_test(nms wb_nms)
# ------------------------------------------------------------------------------
# wb_ac
# ------------------------------------------------------------------------------
SET(SRCS wb_ac.cc)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
add_executable(wb_ac ${HDRS} ${SRCS})
add_dependencies(wb_ac waflzcore)
target_link_libraries(wb_ac ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_ac PROPERTIES OUTPUT_NAME "wb_ac")
add_test(ac wb_ac)
# ------------------------------------------------------------------------------
# wb_byte_range
# ------------------------------------------------------------------------------
SET(SRCS wb_byte_range.cc)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
add_executable(wb_byte_range ${HDRS} ${SRCS})
add_dependencies(wb_byte_range waflzcore)
target_link_libraries(wb_byte_range ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_byte_range PROPERTIES OUTPUT_NAME "wb_byte_range")
add_test(byte_range wb_byte_range)
# ------------------------------------------------------------------------------
# wb_luhn
# ------------------------------------------------------------------------------
SET(SRCS wb_luhn.cc)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
add_executable(wb_luhn ${HDRS} ${SRCS})
add_dependencies(wb_luhn waflzcore)
target_link_libraries(wb_luhn ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_luhn PROPERTIES OUTPUT_NAME "wb_luhn")
add_test(luhn wb_luhn)
# ------------------------------------------------------------------------------
# wb_regex
# ------------------------------------------------------------------------------
SET(SRCS wb_regex.cc)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
add_executable(wb_regex ${HDRS} ${SRCS})
add_dependencies(wb_regex waflzcore)
target_link_libraries(wb_regex ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_regex PROPERTIES OUTPUT_NAME "wb_regex")
add_test(regex wb_regex)

