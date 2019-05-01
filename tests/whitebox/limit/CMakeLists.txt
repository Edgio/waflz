# ----------------------------------------------------------------------------
# Copyright (C) 2018 Verizon.  All Rights Reserved.
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
cmake_minimum_required(VERSION 2.8.0)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_BINARY_DIR}
  ${CMAKE_BINARY_DIR}/proto
)
# ------------------------------------------------------------------------------
# seem to require this for lzo linking
# ------------------------------------------------------------------------------
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -no-pie")
# ------------------------------------------------------------------------------
# wb_rl_op
# ------------------------------------------------------------------------------
SET(SRCS wb_rl_op.cc)
add_executable(wb_rl_op ${HDRS} ${SRCS})
add_dependencies(wb_rl_op waflzcore)
target_link_libraries(wb_rl_op ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_rl_op PROPERTIES OUTPUT_NAME "wb_rl_op")
add_test(rl_op wb_rl_op)
# ------------------------------------------------------------------------------
# wb_rl_op
# ------------------------------------------------------------------------------
SET(SRCS wb_challenge.cc)
add_executable(wb_challenge ${HDRS} ${SRCS})
add_dependencies(wb_challenge waflzcore)
target_link_libraries(wb_challenge ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_challenge PROPERTIES OUTPUT_NAME "wb_challenge")
add_test(challenge wb_challenge)
# ------------------------------------------------------------------------------
# wb_enforcer
# ------------------------------------------------------------------------------
SET(SRCS wb_enforcer.cc)
add_executable(wb_enforcer ${HDRS} ${SRCS})
add_dependencies(wb_enforcer waflzcore)
target_link_libraries(wb_enforcer ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_enforcer PROPERTIES OUTPUT_NAME "wb_enforcer")
add_test(enforcer wb_enforcer)

