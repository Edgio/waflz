# ----------------------------------------------------------------------------
# Copyright (C) 2016 Verizon.  All Rights Reserved.
# All Rights Reserved
#
#   Author: Reed P Morrison
#   Date:   09/13/2016
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
cmake_minimum_required(VERSION 3.5)
# include source and test directories
# ------------------------------------------------------------------------------
# apps
# ------------------------------------------------------------------------------
include_directories(${CMAKE_SOURCE_DIR}/sub/is2)
add_subdirectory(wjc)
add_subdirectory(waflz_dump)
add_subdirectory(waflz_server)
# ----------------------------------------------------------
# only build scopez server if RATE_LIMITING enabled
# ----------------------------------------------------------
if (BUILD_RATE_LIMITING)
add_subdirectory(scopez_server)
endif()
#add_subdirectory(wpc)
