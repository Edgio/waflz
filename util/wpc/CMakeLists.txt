# Project setup
project(waflz)
cmake_minimum_required(VERSION 3.5)
if (POLICY CMP0050)
    cmake_policy(SET CMP0050 OLD)
endif()
# header files to install
LIST(APPEND INST_HDRS ${HDRS})
# include paths
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}/proto
    ../../include
    ../lib
    ../../ext
)
#add_definitions(-std=c++0x)
# Source files
SET(SRCS
    wpc.cc
)
# Headers
SET(HDRS)
# ------------------------------------------------------------------------------
# build and install
# ------------------------------------------------------------------------------
add_executable(wpc_cmd ${HDRS} ${SRCS})
add_dependencies(wpc_cmd waflzcore)
SET_TARGET_PROPERTIES(wpc_cmd PROPERTIES OUTPUT_NAME "wpc")
target_link_libraries(wpc_cmd
        ${DEBUG_LIBRARIES}
        ${CMAKE_BINARY_DIR}/src/lib/libwaflzcore.a
        ${LIBRARIES})
install(TARGETS wpc_cmd
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin/
        COMPONENT Executables
        )