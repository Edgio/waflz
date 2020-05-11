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
cmake_minimum_required(VERSION 3.5)
# ----------------------------------------------------------
# wb_file_util
# ----------------------------------------------------------
SET(SRCS
  wb_file_util.cc
)

find_path(WAFLZ_INC waflz/def.h
            PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../../include )
find_path(WAFLZ_SRC_DIR support/string_util.h
            PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../../src )

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${WAFLZ_INC}
  ${WAFLZ_SRC_DIR}
)
add_waflz_wb_test(file_util)
add_waflz_wb_test(string_util)
add_waflz_wb_test(time_util)
add_waflz_wb_test(geoip2_mmdb)
add_waflz_wb_test(md5)
