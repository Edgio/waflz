# ----------------------------------------------------------------------------
# Copyright (C) 2015 Verizon.  All Rights Reserved.
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
cmake_minimum_required(VERSION 3.5)
set(CMAKE_CXX_FLAGS "-Wall -Weffc++ -Werror -std=c++11")
# ------------------------------------------------------------------------------
# header files to install
# ------------------------------------------------------------------------------
LIST(APPEND INST_HDRS ${HDRS})
# ------------------------------------------------------------------------------
# include paths
# ------------------------------------------------------------------------------
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/ext
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_BINARY_DIR}/proto
)
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
#add_definitions(-std=c++0x)
# ------------------------------------------------------------------------------
# source files
# ------------------------------------------------------------------------------
SET(SRCS waflz_dump.cc)
# ------------------------------------------------------------------------------
# Tell the build system protobuf files are automatically generated
# ------------------------------------------------------------------------------
set_source_files_properties(
    ${CMAKE_BINARY_DIR}/proto/waflz.pb.h
    ${CMAKE_BINARY_DIR}/proto/waflz.pb.cc
    PROPERTIES GENERATED TRUE
)
# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------
SET(HDRS
)
# ------------------------------------------------------------------------------
# build and install waflz_dump
# ------------------------------------------------------------------------------
add_executable(waflz_dump ${HDRS} ${SRCS})
add_dependencies(waflz_dump waflzcore)
SET_TARGET_PROPERTIES(waflz_dump PROPERTIES OUTPUT_NAME "waflz_dump")
target_link_libraries(waflz_dump
  ${DEBUG_LIBRARIES}
  ${CMAKE_BINARY_DIR}/src/libwaflzcore.a
  ${LIBRARIES}
)
install(TARGETS waflz_dump
  DESTINATION ${CMAKE_INSTALL_PREFIX}/bin/
  COMPONENT Executables
)
