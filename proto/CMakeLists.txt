# ------------------------------------------------------------------------------
# TODO boilerplate
# ------------------------------------------------------------------------------
project (waflz)
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
    OUTPUT config_pb2.py
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/config.proto --python_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/config.proto
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
    ${CMAKE_BINARY_DIR}/proto/action_pb2.py
    ${CMAKE_BINARY_DIR}/proto/rule_pb2.py
    ${CMAKE_BINARY_DIR}/proto/config_pb2.py
    ${CMAKE_BINARY_DIR}/proto/event_pb2.py
    ${CMAKE_BINARY_DIR}/proto/request_info_pb2.py
    ${CMAKE_BINARY_DIR}/proto/acl_pb2.py
    ${CMAKE_BINARY_DIR}/proto/scope_pb2.py
    ${CMAKE_BINARY_DIR}/proto/limit_pb2.py
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
    OUTPUT config.pb.cc config.pb.h
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/config.proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/config.proto
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
    ${CMAKE_BINARY_DIR}/proto/action.pb.cc
    ${CMAKE_BINARY_DIR}/proto/action.pb.h
    ${CMAKE_BINARY_DIR}/proto/rule.pb.cc
    ${CMAKE_BINARY_DIR}/proto/rule.pb.h
    ${CMAKE_BINARY_DIR}/proto/config.pb.cc
    ${CMAKE_BINARY_DIR}/proto/config.pb.h
    ${CMAKE_BINARY_DIR}/proto/event.pb.cc
    ${CMAKE_BINARY_DIR}/proto/event.pb.h
    ${CMAKE_BINARY_DIR}/proto/request_info.pb.cc
    ${CMAKE_BINARY_DIR}/proto/request_info.pb.h
    ${CMAKE_BINARY_DIR}/proto/acl.pb.cc
    ${CMAKE_BINARY_DIR}/proto/acl.pb.h
    ${CMAKE_BINARY_DIR}/proto/scope.pb.cc
    ${CMAKE_BINARY_DIR}/proto/scope.pb.h
    ${CMAKE_BINARY_DIR}/proto/limit.pb.cc
    ${CMAKE_BINARY_DIR}/proto/limit.pb.h
)
# ------------------------------------------------------------------------------
# Source files
# ------------------------------------------------------------------------------
set(SRCS
    action.pb.cc
    rule.pb.cc
    config.pb.cc
    event.pb.cc
    request_info.pb.cc
    acl.pb.cc
    scope.pb.cc
    limit.pb.cc
)
# ------------------------------------------------------------------------------
# Header files
# ------------------------------------------------------------------------------
set(HDRS
    action.pb.h
    rule.pb.h
    config.pb.h
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
SET(INST_HDRS ${HDRS})
