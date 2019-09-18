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
# Project setup
project(waflz)
cmake_minimum_required(VERSION 2.8.0)
# ----------------------------------------------------------
# wb_file_util
# ----------------------------------------------------------
SET(SRCS
  wb_file_util.cc
)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
)
add_executable(wb_file_util ${HDRS} ${SRCS})
add_dependencies(wb_file_util waflzcore)
target_link_libraries(wb_file_util ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_file_util PROPERTIES OUTPUT_NAME "wb_file_util")
add_test(file_util wb_file_util)
# ----------------------------------------------------------
# wb_string_util
# ----------------------------------------------------------
SET(SRCS
  wb_string_util.cc
)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
)
add_executable(wb_string_util ${HDRS} ${SRCS})
add_dependencies(wb_string_util waflzcore)
target_link_libraries(wb_string_util ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_string_util PROPERTIES OUTPUT_NAME "wb_string_util")
add_test(string_util wb_string_util)
# ----------------------------------------------------------
# wb_time_util
# ----------------------------------------------------------
SET(SRCS
  wb_time_util.cc
)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
)
add_executable(wb_time_util ${HDRS} ${SRCS})
add_dependencies(wb_time_util waflzcore)
target_link_libraries(wb_time_util ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_time_util PROPERTIES OUTPUT_NAME "wb_time_util")
add_test(time_util wb_time_util)
# ----------------------------------------------------------
# wb_geoip2_mmdb
# ----------------------------------------------------------
SET(SRCS
  wb_geoip2_mmdb.cc
)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
)
add_executable(wb_geoip2_mmdb ${HDRS} ${SRCS})
add_dependencies(wb_geoip2_mmdb waflzcore)
target_link_libraries(wb_geoip2_mmdb
  ${DEBUG_LIBRARIES}
  compiled_catch
  ${CMAKE_BINARY_DIR}/src/libwaflzcore.a
  ${LIBRARIES}
)
SET_TARGET_PROPERTIES(wb_geoip2_mmdb PROPERTIES OUTPUT_NAME "wb_geoip2_mmdb")
add_test(geoip2_mmdb wb_geoip2_mmdb)
# ----------------------------------------------------------
# wb_md5
# ----------------------------------------------------------
SET(SRCS
  wb_md5.cc
)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
)
add_executable(wb_md5 ${HDRS} ${SRCS})
add_dependencies(wb_md5 waflzcore)
target_link_libraries(wb_md5 ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_md5 PROPERTIES OUTPUT_NAME "wb_md5")
add_test(md5 wb_md5)
