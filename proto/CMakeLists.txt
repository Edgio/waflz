# ------------------------------------------------------------------------------
# TODO boilerplate
# ------------------------------------------------------------------------------
project (waflz)
set(CMAKE_VERBOSE_MAKEFILE TRUE)
cmake_minimum_required(VERSION 3.5)

message("Doing Proto stuff probably in waflz: bindir: ${CMAKE_CURRENT_BINARY_DIR}")

# ------------------------------------------------------------------------------
# TODO Create PROTOBUF_GENERATE_PYTHON command
# for cmake...
# ------------------------------------------------------------------------------
# Generate python bindings
# ------------------------------------------------------------------------------
add_custom_command(
    OUTPUT action_pb2.py
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/action.proto --python_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/action.proto
)
add_custom_command(
    OUTPUT rule_pb2.py
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/rule.proto --python_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/rule.proto
)
add_custom_command(
    OUTPUT profile_pb2.py
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/profile.proto --python_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/profile.proto
)
add_custom_command(
    OUTPUT event_pb2.py
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/event.proto --python_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/event.proto
)
add_custom_command(
    OUTPUT request_info_pb2.py
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/request_info.proto --python_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/request_info.proto
)
add_custom_command(
    OUTPUT acl_pb2.py
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/acl.proto --python_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/acl.proto
)
add_custom_command(
    OUTPUT scope_pb2.py
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/scope.proto --python_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/scope.proto
)
add_custom_command(
    OUTPUT limit_pb2.py
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/limit.proto --python_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/limit.proto
)

# custom target for protobuf output
add_custom_target(protodata_py_out ALL DEPENDS
    ${CMAKE_CURRENT_BINARY_DIR}/action_pb2.py
    ${CMAKE_CURRENT_BINARY_DIR}/rule_pb2.py
    ${CMAKE_CURRENT_BINARY_DIR}/profile_pb2.py
    ${CMAKE_CURRENT_BINARY_DIR}/event_pb2.py
    ${CMAKE_CURRENT_BINARY_DIR}/request_info_pb2.py
    ${CMAKE_CURRENT_BINARY_DIR}/acl_pb2.py
    ${CMAKE_CURRENT_BINARY_DIR}/scope_pb2.py
    ${CMAKE_CURRENT_BINARY_DIR}/limit_pb2.py
)
# ------------------------------------------------------------------------------
# protoc generation
# ------------------------------------------------------------------------------
add_custom_command(
    OUTPUT action.pb.cc action.pb.h
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/action.proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/action.proto
    )
add_custom_command(
    OUTPUT rule.pb.cc rule.pb.h
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/rule.proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/rule.proto
    )
add_custom_command(
    OUTPUT profile.pb.cc profile.pb.h
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/profile.proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/profile.proto
    )
add_custom_command(
    OUTPUT event.pb.cc event.pb.h
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/event.proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/event.proto
    )
add_custom_command(
    OUTPUT request_info.pb.cc request_info.pb.h
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/request_info.proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/request_info.proto
    )
add_custom_command(
    OUTPUT acl.pb.cc acl.pb.h
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/acl.proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/acl.proto
    )
add_custom_command(
    OUTPUT scope.pb.cc scope.pb.h
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/scope.proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/scope.proto
    )
add_custom_command(
    OUTPUT limit.pb.cc limit.pb.h
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/limit.proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/limit.proto
    )
# ------------------------------------------------------------------------------
# custom target for protobuf output
# ------------------------------------------------------------------------------
add_custom_target(protobuf_cpp_out ALL DEPENDS
    ${CMAKE_CURRENT_BINARY_DIR}/action.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/action.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/rule.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/rule.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/profile.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/profile.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/event.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/event.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/request_info.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/request_info.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/acl.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/acl.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/scope.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/scope.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/limit.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/limit.pb.h
)
# ------------------------------------------------------------------------------
# Source files
# ------------------------------------------------------------------------------
set(WAFLZ_PROTOBUF_SOURCES
    action.pb.cc
    rule.pb.cc
    profile.pb.cc
    event.pb.cc
    request_info.pb.cc
    acl.pb.cc
    scope.pb.cc
    limit.pb.cc
)
# ------------------------------------------------------------------------------
# Header files
# ------------------------------------------------------------------------------
set(WAFLZ_PROTOBUF_HEADERS
    action.pb.h
    rule.pb.h
    profile.pb.h
    event.pb.h
    request_info.pb.h
    acl.pb.h
    scope.pb.h
    limit.pb.h
)
# ------------------------------------------------------------------------------
# Set INST_HDRS to ensure the build-time generated
# headers are included
# ------------------------------------------------------------------------------
SET(INST_HDRS ${WAFLZ_PROTOBUF_HEADERS})
