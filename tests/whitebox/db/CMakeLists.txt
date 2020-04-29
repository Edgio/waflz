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
# wb_kycb_db
# ------------------------------------------------------------------------------
SET(SRCS wb_kycb_db.cc)
add_executable(wb_kycb_db ${HDRS} ${SRCS})
add_dependencies(wb_kycb_db waflzcore)
target_link_libraries(wb_kycb_db ${DEBUG_LIBRARIES} waflz_compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_kycb_db PROPERTIES OUTPUT_NAME "wb_kycb_db")
add_test(kycb_db wb_kycb_db)
# ------------------------------------------------------------------------------
# wb_redis_db
# NOTE -this requires running redis instance
# ------------------------------------------------------------------------------
SET(SRCS wb_redis_db.cc)
add_executable(wb_redis_db ${HDRS} ${SRCS})
add_dependencies(wb_redis_db waflzcore)
target_link_libraries(wb_redis_db ${DEBUG_LIBRARIES} waflz_compiled_catch ${CMAKE_BINARY_DIR}/src/libwaflzcore.a ${LIBRARIES})
SET_TARGET_PROPERTIES(wb_redis_db PROPERTIES OUTPUT_NAME "wb_redis_db")
# commenting out -requires redis to run...
#add_test(redis_db wb_redis_db)
