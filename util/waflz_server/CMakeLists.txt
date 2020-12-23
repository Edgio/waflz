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
if(BUILD_RATE_LIMITING)
list(APPEND SRCS
  sx_limit.cc
)
endif()
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
  ${DEBUG_LIBRARIES}
  ${CMAKE_BINARY_DIR}/src/libwaflzcore.a
  ${CMAKE_BINARY_DIR}/submodule_is2-prefix/src/submodule_is2-build/src/libis2.a
  ${LIBRARIES}
)
install(TARGETS waflz_server
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin/
        COMPONENT Executables
        )
