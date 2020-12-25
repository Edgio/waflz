# ------------------------------------------------------------------------------
# project setup
# ------------------------------------------------------------------------------
project(waflz)
cmake_minimum_required(VERSION 3.5)
# TODO set later...
#set(CMAKE_CXX_FLAGS "-Wall -Weffc++ -Werror -std=c++11")
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
  ${CMAKE_SOURCE_DIR}/util/waflz_server/
  ${CMAKE_SOURCE_DIR}/sub/is2/include
)
# ------------------------------------------------------------------------------
# sources
# ------------------------------------------------------------------------------
SET(SRCS
  ${CMAKE_SOURCE_DIR}/util/waflz_server/cb.cc
  sx_scopes.cc
  scopez_server.cc
)
# ------------------------------------------------------------------------------
# headers
# ------------------------------------------------------------------------------
SET(HDRS)
# ------------------------------------------------------------------------------
# exe
# ------------------------------------------------------------------------------
add_executable(scopez_server ${HDRS} ${SRCS})
add_dependencies(scopez_server waflzcore)
add_dependencies(scopez_server submodule_is2)
SET_TARGET_PROPERTIES(scopez_server PROPERTIES OUTPUT_NAME "scopez_server")
target_link_libraries(scopez_server
  ${DEBUG_LIBRARIES}
  ${CMAKE_BINARY_DIR}/src/libwaflzcore.a
  ${CMAKE_BINARY_DIR}/submodule_is2-prefix/src/submodule_is2-build/src/libis2.a
  m
  ${LIBRARIES}
)
install(TARGETS scopez_server
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin/
        COMPONENT Executables
        )
