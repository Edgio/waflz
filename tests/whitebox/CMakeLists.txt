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
# Project setup
# ------------------------------------------------------------------------------
project(waflz)
cmake_minimum_required(VERSION 3.5)

macro (add_waflz_wb_test test_name)
    # SET(SRCS wb_matched_data.cc)
    add_executable("wb_${test_name}" "wb_${test_name}.cc")
    target_link_libraries("wb_${test_name}" ${DEBUG_LIBRARIES} waflz_compiled_catch waflzcore ${LIBRARIES})
    add_test(${test_name} "wb_${test_name}")
endmacro()

# ------------------------------------------------------------------------------
# build catch
# ------------------------------------------------------------------------------
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ../../ext/)
add_library(waflz_compiled_catch STATIC ${CMAKE_CURRENT_SOURCE_DIR}/../../ext/catch/catch.hpp _catch.cc)
# ------------------------------------------------------------------------------
# build tests
# ------------------------------------------------------------------------------
add_subdirectory(support)
add_subdirectory(jspb)
add_subdirectory(core)
add_subdirectory(op)
add_subdirectory(parser)
# ------------------------------------------------------------------------------
# if rate-limiting -add rate-limiting related tests
# ------------------------------------------------------------------------------
if(BUILD_RATE_LIMITING)
add_subdirectory(db)
add_subdirectory(limit)
endif()
