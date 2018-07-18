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
    OUTPUT enforcement_pb2.py
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/enforcement.proto --python_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/enforcement.proto
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
    OUTPUT acl.py
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/acl.proto --python_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/acl.proto
)

# custom target for protobuf output
add_custom_target(protodata_py_out ALL DEPENDS
    ${CMAKE_BINARY_DIR}/proto/enforcement_pb2.py
    ${CMAKE_BINARY_DIR}/proto/rule_pb2.py
    ${CMAKE_BINARY_DIR}/proto/config_pb2.py
    ${CMAKE_BINARY_DIR}/proto/event_pb2.py
    ${CMAKE_BINARY_DIR}/proto/request_info_pb2.py
    ${CMAKE_BINARY_DIR}/proto/acl.py
)
# ------------------------------------------------------------------------------
# protoc generation
# ------------------------------------------------------------------------------
add_custom_command(
    OUTPUT enforcement.pb.cc enforcement.pb.h
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/enforcement.proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/enforcement.proto
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
# ------------------------------------------------------------------------------
# custom target for protobuf output
# ------------------------------------------------------------------------------
add_custom_target(protobuf_cpp_out ALL DEPENDS
    ${CMAKE_BINARY_DIR}/proto/enforcement.pb.cc
    ${CMAKE_BINARY_DIR}/proto/enforcement.pb.h
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
)
# ------------------------------------------------------------------------------
# Source files
# ------------------------------------------------------------------------------
set(SRCS
    enforcement.pb.cc
    rule.pb.cc
    config.pb.cc
    event.pb.cc
    request_info.pb.cc
    acl.pb.cc
)
# ------------------------------------------------------------------------------
# Header files
# ------------------------------------------------------------------------------
set(HDRS
    enforcement.pb.h
    rule.pb.h
    config.pb.h
    event.pb.h
    request_info.pb.h
    acl.pb.h
)
# ------------------------------------------------------------------------------
# Set INST_HDRS to ensure the build-time generated
# headers are included
# ------------------------------------------------------------------------------
SET(INST_HDRS ${HDRS})
