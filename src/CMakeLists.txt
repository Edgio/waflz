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
project(waflz C CXX)
cmake_minimum_required(VERSION 3.5)
if (POLICY CMP0050)
    cmake_policy(SET CMP0050 OLD)
endif()
# ------------------------------------------------------------------------------
# Can't add for now...
# ------------------------------------------------------------------------------
add_definitions(-DHAVE_CONFIG_H)
# ------------------------------------------------------------------------------
# header files to install
# ------------------------------------------------------------------------------
LIST(APPEND INST_HDRS ${HDRS})
# ------------------------------------------------------------------------------
# include paths
# ------------------------------------------------------------------------------
include_directories(
    #${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    # ------------------------------------------------------
    # proto
    # ------------------------------------------------------
    ${CMAKE_BINARY_DIR}/proto
    # ------------------------------------------------------
    # yajl
    # ------------------------------------------------------
    ${CMAKE_BINARY_DIR}/ext_yajl-prefix/src/yajl-2.1.1/include
    # ------------------------------------------------------
    # waflz include
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    # ------------------------------------------------------
    # cityhash libs
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/cityhash
    # ------------------------------------------------------
    # libinjection
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/libinjection/src
    # ------------------------------------------------------
    # libmaxminddb
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src
    # ------------------------------------------------------
    # external libs
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext
    ${CMAKE_SOURCE_DIR}/ext/yajl
    /usr/include/libxml2
)
# ------------------------------------------------------------------------------
# source files
# ------------------------------------------------------------------------------
SET(SRCS
    # ------------------------------------------------------
    # libmaxminddb
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src/data-pool.c
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src/maxminddb.c
    # ------------------------------------------------------
    # yajl
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_alloc.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_gen.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_parser.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_version.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_buf.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_encode.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_lex.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_tree.c
    # ------------------------------------------------------
    # base64
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/base64/base64.cc
    # ------------------------------------------------------
    # json protobuf
    # ------------------------------------------------------
    jspb/jspb.cc
    # ------------------------------------------------------
    # support
    # ------------------------------------------------------
    support/city.cc
    support/time_util.cc
    support/geoip2_mmdb.cc
    support/file_util.cc
    support/string_util.cc
    support/trace.cc
    support/ndebug.cc
    support/base64.cc
    # ------------------------------------------------------
    # libinjection
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/libinjection/src/libinjection_html5.c
    ${CMAKE_SOURCE_DIR}/ext/libinjection/src/libinjection_sqli.c
    ${CMAKE_SOURCE_DIR}/ext/libinjection/src/libinjection_xss.c
    # ------------------------------------------------------
    # operators
    # ------------------------------------------------------
    modsecurity/config_parser.cc
    # ------------------------------------------------------
    # operators
    # ------------------------------------------------------
    op/regex.cc
    op/luhn.cc
    op/nms.cc
    op/ac.cc
    op/byte_range.cc
    # ------------------------------------------------------
    # core
    # ------------------------------------------------------
    core/waf.cc
    core/acl.cc
    core/engine.cc
    core/profile.cc
    core/instance.cc
    core/instances.cc
    core/decode.cc
    core/rqst_ctx.cc
    core/var.cc
    core/tx.cc
    core/op.cc
    core/macro.cc
    core/render.cc
    core/scopes.cc
    core/scopes_configs.cc
    core/rules.cc
    core/challenge.cc
    # ------------------------------------------------------
    # parsers
    # ------------------------------------------------------
    parser/parser_url_encoded.cc
    parser/parser_xml.cc
    parser/parser_json.cc
)
# ------------------------------------------------------------------------------
# if rate-limiting...
# ------------------------------------------------------------------------------
if(BUILD_RATE_LIMITING)
list(APPEND SRCS
    #---------------------------------------------
    # ectoken
    #---------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/ectoken/ectoken_v3.cc
    ${CMAKE_SOURCE_DIR}/ext/ectoken/base64.cc
    # ------------------------------------------------------
    # db
    # ------------------------------------------------------
    db/kycb_db.cc
    db/redis_db.cc
    # ------------------------------------------------------
    # limit
    # ------------------------------------------------------
    limit/rl_obj.cc
    limit/enforcer.cc
    limit/config.cc
    limit/configs.cc
    limit/limit.cc
)
endif()
# ------------------------------------------------------------------------------
# c source
# ------------------------------------------------------------------------------
SET_SOURCE_FILES_PROPERTIES(
    # ------------------------------------------------------
    # libmaxminddb
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src/data-pool.c
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src/maxminddb.c
    # ------------------------------------------------------
    # yajl
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_alloc.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_gen.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_parser.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_version.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_buf.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_encode.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_lex.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_tree.c
    # ------------------------------------------------------
    # libinjection
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/libinjection/src/libinjection_html5.c
    ${CMAKE_SOURCE_DIR}/ext/libinjection/src/libinjection_sqli.c
    ${CMAKE_SOURCE_DIR}/ext/libinjection/src/libinjection_xss.c
    # ------------------------------------------------------
    # properties
    # ------------------------------------------------------
    PROPERTIES LANGUAGE C
)
set(CMAKE_C_FLAGS "-std=c99")
set(CMAKE_CXX_FLAGS "-Wall -Weffc++ -Werror -std=c++11")
# ------------------------------------------------------------------------------
# headers
# ------------------------------------------------------------------------------
SET(HDRS
    ${CMAKE_SOURCE_DIR}/include/waflz/acl.h
    ${CMAKE_SOURCE_DIR}/include/waflz/arg.h
    ${CMAKE_SOURCE_DIR}/include/waflz/atomic.h
    ${CMAKE_SOURCE_DIR}/include/waflz/challenge.h
    ${CMAKE_SOURCE_DIR}/include/waflz/city.h
    ${CMAKE_SOURCE_DIR}/include/waflz/config_parser.h
    ${CMAKE_SOURCE_DIR}/include/waflz/def.h
    ${CMAKE_SOURCE_DIR}/include/waflz/engine.h
    ${CMAKE_SOURCE_DIR}/include/waflz/geoip2_mmdb.h
    ${CMAKE_SOURCE_DIR}/include/waflz/instance.h
    ${CMAKE_SOURCE_DIR}/include/waflz/instances.h
    ${CMAKE_SOURCE_DIR}/include/waflz/parser.h
    ${CMAKE_SOURCE_DIR}/include/waflz/profile.h
    ${CMAKE_SOURCE_DIR}/include/waflz/render.h
    ${CMAKE_SOURCE_DIR}/include/waflz/rqst_ctx.h
    ${CMAKE_SOURCE_DIR}/include/waflz/rules.h
    ${CMAKE_SOURCE_DIR}/include/waflz/scopes_configs.h
    ${CMAKE_SOURCE_DIR}/include/waflz/scopes.h
    ${CMAKE_SOURCE_DIR}/include/waflz/trace.h
    ${CMAKE_SOURCE_DIR}/include/waflz/waf.h
    ${CMAKE_SOURCE_DIR}/include/waflz/waflz.h
    # ------------------------------------------------------
    # db
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/include/waflz/kv_db.h
    ${CMAKE_SOURCE_DIR}/include/waflz/kycb_db.h
    ${CMAKE_SOURCE_DIR}/include/waflz/redis_db.h
    # ------------------------------------------------------
    # limit
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/include/waflz/config.h
    ${CMAKE_SOURCE_DIR}/include/waflz/configs.h
    ${CMAKE_SOURCE_DIR}/include/waflz/enforcer.h
    ${CMAKE_SOURCE_DIR}/include/waflz/limit.h
    ${CMAKE_SOURCE_DIR}/include/waflz/rl_obj.h
    # ------------------------------------------------------
    # protocol buffers
    # ------------------------------------------------------
    ${CMAKE_BINARY_DIR}/proto/acl.pb.h
    ${CMAKE_BINARY_DIR}/proto/action.pb.h
    ${CMAKE_BINARY_DIR}/proto/event.pb.h
    ${CMAKE_BINARY_DIR}/proto/limit.pb.h
    ${CMAKE_BINARY_DIR}/proto/profile.pb.h
    ${CMAKE_BINARY_DIR}/proto/request_info.pb.h
    ${CMAKE_BINARY_DIR}/proto/rule.pb.h
    ${CMAKE_BINARY_DIR}/proto/scope.pb.h
)
# ------------------------------------------------------------------------------
# Tell the build system protobuf files are automatically generated
# ------------------------------------------------------------------------------
SET(PB_SRCS
    ${WAFLZ_PROTO_HDRS} ${WAFLZ_PROTO_SRCS}
)
set_source_files_properties(${PB_SRCS} PROPERTIES GENERATED TRUE)
set_source_files_properties(${PB_SRCS} PROPERTIES COMPILE_FLAGS '-Wno-effc++')
# ------------------------------------------------------------------------------
# Python support
# ------------------------------------------------------------------------------
SET(PY_INST
    ${CMAKE_BINARY_DIR}/proto/profile_pb2.py
    ${CMAKE_BINARY_DIR}/proto/action_pb2.py
    ${CMAKE_BINARY_DIR}/proto/event_pb2.py
    ${CMAKE_BINARY_DIR}/proto/request_info_pb2.py
    ${CMAKE_BINARY_DIR}/proto/rule_pb2.py
    ${CMAKE_BINARY_DIR}/proto/acl_pb2.py
)
# ------------------------------------------------------------------------------
# rate-limiting proto
# ------------------------------------------------------------------------------
if(BUILD_RATE_LIMITING)
    list(APPEND PY_INST
    ${CMAKE_BINARY_DIR}/proto/scope_pb2.py
    ${CMAKE_BINARY_DIR}/proto/limit_pb2.py
    )
endif()
install(FILES ${PY_INST}
    DESTINATION include/waflz-py
    COMPONENT Headers
)
# ------------------------------------------------------------------------------
# library
# ------------------------------------------------------------------------------
add_library(waflzcore STATIC ${SRCS} ${PB_SRCS})

target_include_directories(waflzcore PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/proto/ ${CMAKE_BINARY_DIR}/)


SET_TARGET_PROPERTIES(waflzcore
  PROPERTIES
  POSITION_INDEPENDENT_CODE ON
)

# Create symlink for libwaflz.so.<soversion>
SET_TARGET_PROPERTIES(waflzcore
  PROPERTIES
  SOVERSION 0
)

# Add install target for the library
install(TARGETS waflzcore
  ARCHIVE DESTINATION lib
  COMPONENT Libraries
)

# Add install target for header files
install(FILES ${HDRS}
  DESTINATION include/waflz
  COMPONENT Headers
)

