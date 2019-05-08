# ----------------------------------------------------------------------------
# Copyright (C) 2017 Verizon.  All Rights Reserved.
# All Rights Reserved
#
#   Author: Reed P Morrison
#   Date:   02/24/2017  
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
# ------------------------------------------------------------------------------
# ???
# ------------------------------------------------------------------------------
LIST(APPEND INST_HDRS ${HDRS})
# ------------------------------------------------------------------------------
# include paths
# ------------------------------------------------------------------------------
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_BINARY_DIR}/proto
  ${CMAKE_SOURCE_DIR}/ext
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/sub/is2/include
)
# ------------------------------------------------------------------------------
# sources
# ------------------------------------------------------------------------------
SET(SRCS
  cb.cc
  sx_profile.cc
  sx_instance.cc
  sx_modsecurity.cc
  waflz_server.cc
)
# ------------------------------------------------------------------------------
# headers
# ------------------------------------------------------------------------------
SET(HDRS)
# ------------------------------------------------------------------------------
# exe
# ------------------------------------------------------------------------------
add_executable(waflz_server ${HDRS} ${SRCS})
add_dependencies(waflz_server waflzcore)
add_dependencies(waflz_server submodule_is2)
SET_TARGET_PROPERTIES(waflz_server PROPERTIES OUTPUT_NAME "waflz_server")
target_link_libraries(waflz_server
  asan
  ${CMAKE_BINARY_DIR}/src/libwaflzcore.a
  ${CMAKE_BINARY_DIR}/submodule_is2-prefix/src/submodule_is2-build/src/libis2.a
  pthread
  ssl
  crypto
  xml2
  protobuf
  pcre
  # rate-limiting only...
  hiredis
  kyotocabinet
)
install(TARGETS waflz_server
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin/
        COMPONENT Executables
        )
