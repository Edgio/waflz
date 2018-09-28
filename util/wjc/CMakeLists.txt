# ----------------------------------------------------------------------------
# Copyright (C) 2014 Verizon.  All Rights Reserved.
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
cmake_minimum_required(VERSION 2.6.0)
if (POLICY CMP0050)
    cmake_policy(SET CMP0050 OLD)
endif()
# ------------------------------------------------------------------------------
# header files to install
# ------------------------------------------------------------------------------
LIST(APPEND INST_HDRS ${HDRS})
# ------------------------------------------------------------------------------
# include paths
# ------------------------------------------------------------------------------
include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    # --------------------------------------------
    # proto
    # --------------------------------------------
    ${CMAKE_BINARY_DIR}/proto
    # --------------------------------------------
    # waflz support
    # --------------------------------------------
    ../../include
    # --------------------------------------------
    # waflz reuse
    # --------------------------------------------
    ../lib
    # --------------------------------------------
    # external libs
    # --------------------------------------------
    ../../ext
    # --------------------------------------------
    # Kooky modsecurity includes
    # --------------------------------------------
    ../../ext/modsecurity
    ../../ext/modsecurity/apache2
    /usr/include/libxml2
)
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
#add_definitions(-std=c++0x)
# ------------------------------------------------------------------------------
# source files
# ------------------------------------------------------------------------------
SET(SRCS wjc.cc)
# ------------------------------------------------------------------------------
# headers
# ------------------------------------------------------------------------------
SET(HDRS)
# ------------------------------------------------------------------------------
# build and install
# ------------------------------------------------------------------------------
add_executable(wjc_cmd ${HDRS} ${SRCS})
add_dependencies(wjc_cmd waflzcore)
SET_TARGET_PROPERTIES(wjc_cmd PROPERTIES OUTPUT_NAME "wjc")
target_link_libraries(wjc_cmd
        ${DEBUG_LIBRARIES}
        ${CMAKE_BINARY_DIR}/src/libwaflzcore.a
        ${LIBRARIES})
install(TARGETS wjc_cmd
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin/
        COMPONENT Executables
        )