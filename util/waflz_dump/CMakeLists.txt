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
