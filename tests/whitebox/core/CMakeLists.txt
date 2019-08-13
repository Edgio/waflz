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
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_BINARY_DIR}
  ${CMAKE_BINARY_DIR}/proto
)
# ------------------------------------------------------------------------------
# wb_instances
# ------------------------------------------------------------------------------
SET(SRCS wb_instances.cc)
add_executable(wb_instances ${HDRS} ${SRCS})
add_dependencies(wb_instances waflzcore)
target_link_libraries(wb_instances ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_instances PROPERTIES OUTPUT_NAME "wb_instances")
add_test(instances wb_instances)
# ------------------------------------------------------------------------------
# wb_matched_data
# ------------------------------------------------------------------------------
SET(SRCS wb_matched_data.cc)
add_executable(wb_matched_data ${HDRS} ${SRCS})
add_dependencies(wb_matched_data waflzcore)
target_link_libraries(wb_matched_data ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_matched_data PROPERTIES OUTPUT_NAME "wb_matched_data")
add_test(matched_data wb_matched_data)
# ------------------------------------------------------------------------------
# wb_acl
# ------------------------------------------------------------------------------
SET(SRCS wb_acl.cc)
add_executable(wb_acl ${HDRS} ${SRCS})
add_dependencies(wb_acl waflzcore)
target_link_libraries(wb_acl ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_acl PROPERTIES OUTPUT_NAME "wb_acl")
add_test(acl wb_acl)
# ------------------------------------------------------------------------------
# wb_acl_accesslist
# ------------------------------------------------------------------------------
SET(SRCS wb_acl_accesslist.cc)
add_executable(wb_acl_accesslist ${HDRS} ${SRCS})
add_dependencies(wb_acl_accesslist waflzcore)
target_link_libraries(wb_acl_accesslist ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_acl_accesslist PROPERTIES OUTPUT_NAME "wb_acl_accesslist")
add_test(acl_accesslist wb_acl_accesslist)
# ------------------------------------------------------------------------------
# wb_profile_policies
# ------------------------------------------------------------------------------
SET(SRCS wb_profile_policies.cc)
add_executable(wb_profile_policies ${HDRS} ${SRCS})
add_dependencies(wb_profile_policies waflzcore)
target_link_libraries(wb_profile_policies ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_profile_policies PROPERTIES OUTPUT_NAME "wb_profile_policies")
add_test(profile_policies wb_profile_policies)
# ------------------------------------------------------------------------------
# wb_jspb
# ------------------------------------------------------------------------------
SET(SRCS wb_shell_shock.cc)
add_executable(wb_shell_shock ${HDRS} ${SRCS})
add_dependencies(wb_shell_shock waflzcore)
target_link_libraries(wb_shell_shock ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_shell_shock PROPERTIES OUTPUT_NAME "wb_shell_shock")
add_test(shell_shock wb_shell_shock)
# ------------------------------------------------------------------------------
# wb_decode
# ------------------------------------------------------------------------------
SET(SRCS wb_decode.cc)
add_executable(wb_decode ${HDRS} ${SRCS})
add_dependencies(wb_decode waflzcore)
target_link_libraries(wb_decode ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_decode PROPERTIES OUTPUT_NAME "wb_decode")
add_test(decode wb_decode)
# ------------------------------------------------------------------------------
# wb_op
# ------------------------------------------------------------------------------
SET(SRCS wb_op.cc)
add_executable(wb_op ${HDRS} ${SRCS})
add_dependencies(wb_op waflzcore)
target_link_libraries(wb_op ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_op PROPERTIES OUTPUT_NAME "wb_op")
add_test(op wb_op)
# ------------------------------------------------------------------------------
# wb_var
# ------------------------------------------------------------------------------
SET(SRCS wb_var.cc)
add_executable(wb_var ${HDRS} ${SRCS})
add_dependencies(wb_var waflzcore)
target_link_libraries(wb_var ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_var PROPERTIES OUTPUT_NAME "wb_var")
add_test(var wb_var)
# ------------------------------------------------------------------------------
# wb_tx
# ------------------------------------------------------------------------------
SET(SRCS wb_tx.cc)
add_executable(wb_tx ${HDRS} ${SRCS})
add_dependencies(wb_tx waflzcore)
target_link_libraries(wb_tx ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_tx PROPERTIES OUTPUT_NAME "wb_tx")
add_test(tx wb_tx)
# ------------------------------------------------------------------------------
# wb_render
# ------------------------------------------------------------------------------
SET(SRCS wb_render.cc)
add_executable(wb_render ${HDRS} ${SRCS})
add_dependencies(wb_render waflzcore)
target_link_libraries(wb_render ${DEBUG_LIBRARIES} compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_render PROPERTIES OUTPUT_NAME "wb_render")
add_test(render wb_render)