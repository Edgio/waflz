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
# Project setup
# ------------------------------------------------------------------------------
project(waflz)
cmake_minimum_required(VERSION 2.8.0)
# ------------------------------------------------------------------------------
# Build options
# ------------------------------------------------------------------------------
option(GCC_OPTIONS       "Command line options passed to gcc or 'native' to compile for this hardware" OFF)
option(DEBUG_MODE        "Compile in debug mode." OFF)
option(FORTIFY           "Fortify source." OFF)
option(BUILD_SYMBOLS     "Build with Symbols" OFF)
option(BUILD_TCMALLOC    "Build with tcmalloc" OFF)
option(BUILD_PROFILER    "Enable google cpu and heap profiler support" OFF)
option(BUILD_ASAN        "Build with Address Sanitizer" OFF)
option(BUILD_UBSAN       "Build with Undefined Behavior Sanitizer" OFF)
option(BUILD_TESTS       "Build the unit tests." ON)
option(BUILD_APPS        "Build the apps." OFF)
option(BUILD_CUSTOM_OPENSSL "Build for openssl" OFF)
# ------------------------------------------------------------------------------
# Compiler options
# ------------------------------------------------------------------------------
#add_definitions(-Wall -Werror -Wformat -Wformat-security)
#add_definitions(-pedantic)
# ------------------------------------------------------------------------------
#Add the corrent -std flag, whatever it is
# ------------------------------------------------------------------------------
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG(-Wno-error=misleading-indentation COMPILER_SUPPORTS_MISIDENT)
CHECK_CXX_COMPILER_FLAG(-Wno-error=nonnull-compare COMPILER_SUPPORTS_NONNULL)
CHECK_CXX_COMPILER_FLAG(-std=c++14 COMPILER_SUPPORTS_CXX14)
CHECK_CXX_COMPILER_FLAG(-std=c++0x COMPILER_SUPPORTS_CXX0X)
if(COMPILER_SUPPORTS_CXX14)
  #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
  if(COMPILER_SUPPORTS_MISIDENT)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=misleading-indentation")
  endif()
  if(COMPILER_SUPPORTS_NONNULL)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=nonnull-compare")
  endif()
elseif(COMPILER_SUPPORTS_CXX0X)
  #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
else()
  #message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++0x support. Please use a different C++ compiler.")
endif()
if(BUILD_CUSTOM_OPENSSL)
  INCLUDE_DIRECTORIES("${BUILD_CUSTOM_OPENSSL}/include")
  set(LIBRARIES ${LIBRARIES} "${BUILD_CUSTOM_OPENSSL}/libssl.so")
  set(LIBRARIES ${LIBRARIES} "${BUILD_CUSTOM_OPENSSL}/libcrypto.so")
  add_definitions(-DBUILD_CUSTOM_OPENSSL=1)
else()
  set(LIBRARIES ${LIBRARIES} pthread ssl crypto)
endif()
# ------------------------------------------------------------------------------
# Display the current settings
# ------------------------------------------------------------------------------
message(STATUS "Build Configuration:")
message("")
message("    Build Option                               Variable                Value                 ")
message("    -----------------------------------------------------------------------------------------")
message("    Debug mode:                                " "DEBUG_MODE              " ${DEBUG_MODE})
message("    Fortify Source:                            " "FORTIFY                 " ${FORTIFY})
message("    Install path:                              " "INSTALL_PREFIX          " ${CMAKE_INSTALL_PREFIX})
message("    Build Symbols                              " "BUILD_SYMBOLS           " ${BUILD_SYMBOLS})
message("    Build with tcmalloc:                       " "BUILD_TCMALLOC          " ${BUILD_TCMALLOC})
message("    Enable google cpu/heap profiler support:   " "BUILD_PROFILER          " ${BUILD_PROFILER})
message("    Build with Address Sanitizer:              " "BUILD_ASAN              " ${BUILD_ASAN})
message("    Build with Undefined Behavior Sanitizer:   " "BUILD_UBSAN             " ${BUILD_UBSAN})
message("    Build unit tests:                          " "BUILD_TESTS             " ${BUILD_TESTS})
message("    Build applications:                        " "BUILD_APPS              " ${BUILD_APPS})
message("    Build for custom OpenSSL:                  " "BUILD_CUSTOM_OPENSSL    " ${BUILD_CUSTOM_OPENSSL})
message("")
# ------------------------------------------------------------------------------
# Fortify Options
# ------------------------------------------------------------------------------
if (FORTIFY)
  add_definitions(-D_FORTIFY_SOURCE=2 -O1 -Wl,-z,relro,-z,now)
endif()
# ------------------------------------------------------------------------------
# \brief   Find ubuntu packages based on their (optional) include and (required) library test files
# \details
# \param   output_var_prefix    The prefix for variables output_var_prefix{_INCLUDE_DIR,_LIBS} that are set on success
# \param   include_test_file    The file to look for via find_path to see if it exists anywhere
# \param   library_test_file    The file to look for and add to the LIBRARIES variable
# \param   ubuntu_package       The package to add to CPACK package depends list
# \param   ubuntu_build_package The package to suggest installing to proceed building properly
# ------------------------------------------------------------------------------
macro(find_ubuntu_package output_var_prefix
      include_test_file
      library_test_file
      ubuntu_package
      ubuntu_build_package)
  # handle optional prefix_path arg
  if (${ARGC} EQUAL 6)
          set(prefix_path "${ARGN}")
          message(STATUS "Got prefix path: '${prefix_path}' for package: ${ubuntu_build_package}")
          # set(list_var "${ARGN}")
          # message(STATUS "got ARGC: ${ARGC}")
          # foreach(loop_var IN LISTS list_var)
          #         message(STATUS "got arg: ${loop_var}")
          # endforeach()
  endif()
  if (NOT "${include_test_file}" STREQUAL "")
          find_path(${output_var_prefix}_INCLUDE_DIR ${include_test_file}) # HINTS ${prefix_path} NO_CMAKE_PATH NO_CMAKE_ENVIRONMENT_PATH NO_SYSTEN_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)
          if (${output_var_prefix}_INCLUDE_DIR)
                  #if(NOT "${output_var_prefix}_INCLUDE_DIR" STREQUAL "/usr/include")
                          message(STATUS "Found ${output_var_prefix} include: ${${output_var_prefix}_INCLUDE_DIR}")
                  #endif()
          else()
                  message("aaaa Failed to find ${output_var_prefix} include.  Suggested ubuntu package: ${ubuntu_build_package}")
                  LIST(APPEND MISSING_UBUNTU_PACKAGES "'${ubuntu_build_package}'")
                  SET(FAILED_PACKAGES 1)
          endif()
  endif()
  if (NOT "${library_test_file}" STREQUAL "")
          find_library(${output_var_prefix}_LIBS ${library_test_file} HINTS ${prefix_path} NO_CMAKE_PATH NO_CMAKE_ENVIRONMENT_PATH)
          if (${output_var_prefix}_LIBS)
                  message(STATUS "Found ${output_var_prefix} lib: ${${output_var_prefix}_LIBS}")
                  LIST(APPEND LIBRARIES ${${output_var_prefix}_LIBS})
          else()
                  message("Failed to find ${output_var_prefix} library.  Suggested ubuntu package: ${ubuntu_build_package}")
                  LIST(APPEND MISSING_UBUNTU_PACKAGES "'${ubuntu_build_package}'")
                  SET(FAILED_PACKAGES 1)
          endif()
  endif()
  if (NOT "${ubuntu_package}" STREQUAL "")
          LIST(APPEND CPACK_DEBIAN_PACKAGE_DEPENDS_LIST "${ubuntu_package}")
  endif()
  if (NOT "${ubuntu_build_package}" STREQUAL "")
          LIST(APPEND CPACK_DEBIAN_PACKAGE_BUILDS_DEPENDS_LIST "${ubuntu_build_package}")
  endif()
endmacro(find_ubuntu_package)
# ------------------------------------------------------------------------------
# ASAN
# ------------------------------------------------------------------------------
if (BUILD_ASAN)
  set(DEBUG_LIBRARIES asan ${DEBUG_LIBRARIES})
  add_definitions(-g3 -fno-omit-frame-pointer -fsanitize=address)
  set(DEBUG_MODE ON)
  set(BUILD_PROFILER OFF)
  set(BUILD_TCMALLOC OFF)
# ------------------------------------------------------------------------------
# UBSAN
# ------------------------------------------------------------------------------
elseif (BUILD_UBSAN)
  set(DEBUG_LIBRARIES ubsan ${DEBUG_LIBRARIES})
  add_definitions(-g3 -fno-omit-frame-pointer -fsanitize=undefined -fno-sanitize-recover)
  set(DEBUG_MODE ON)
  set(BUILD_PROFILER OFF)
  set(BUILD_TCMALLOC OFF)
endif()
# ------------------------------------------------------------------------------
# Build PROFILER
# ------------------------------------------------------------------------------
if(BUILD_PROFILER)
  add_definitions(-DENABLE_PROFILER=1)
  find_ubuntu_package(LIBPROFILER google/profiler.h libprofiler.a google-perftools libgoogle-perftools-dev)
  set(LIBRARIES ${LIBRARIES} unwind)
endif()
# ------------------------------------------------------------------------------
# Build TCMALLOC
# ------------------------------------------------------------------------------
if (BUILD_TCMALLOC)
  find_ubuntu_package(LIBTCMALLOC google/tcmalloc.h libtcmalloc.a "" libgoogle-perftools-dev)
  find_ubuntu_package(LIBUNWIND libunwind.h libunwind.a "" libunwind8-dev)
  # yes it's wierd as shit to have to include this again...
  LIST(APPEND LIBRARIES pthread)
endif()
# ------------------------------------------------------------------------------
# Link OpenSSL (crypto)
# ------------------------------------------------------------------------------
find_ubuntu_package(LIBCRYPTO openssl/crypto.h libcrypto.a libssl1.0.0 libssl-dev)
# ------------------------------------------------------------------------------
# Link pcre
# ------------------------------------------------------------------------------
find_ubuntu_package(LIBPCRE pcre.h libpcre.a libpcre.so libpcre3-dev)
# ------------------------------------------------------------------------------
# Link xml2
# ------------------------------------------------------------------------------
find_ubuntu_package(LIBXML2 libxml2/libxml/xmlversion.h libxml2.a libxml2 libxml2-dev)
# ------------------------------------------------------------------------------
# Link ZLIB
# ------------------------------------------------------------------------------
find_ubuntu_package(LIBZ zlib.h libz.a zlib1g zlib1g-dev)
# ------------------------------------------------------------------------------
# Link ZMA
# ------------------------------------------------------------------------------
find_ubuntu_package(LIBZMA "" liblzma.a "" liblzma-dev)
# ------------------------------------------------------------------------------
# Link icu (unicode lib)
# ------------------------------------------------------------------------------
find_ubuntu_package(LIBICUIL8N unicode/uversion.h libicui18n.a libicu libicu-dev)
find_ubuntu_package(LIBICU unicode/uversion.h libicuuc.a libicu libicu-dev)
find_ubuntu_package(LIBICUDATA unicode/uversion.h libicudata.a libicu libicu-dev)
# ------------------------------------------------------------------------------
# Link PROTOBUF
# ------------------------------------------------------------------------------
find_ubuntu_package(LIBPROTOBUF google/protobuf/message.h libprotobuf.a libprotobuf libprotobuf-dev)
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
if (FAILED_PACKAGES)
  LIST(REMOVE_DUPLICATES MISSING_UBUNTU_PACKAGES)
  string(REPLACE ";" " " MISSING_UBUNTU_PACKAGES_STR "${MISSING_UBUNTU_PACKAGES}")
  message(FATAL_ERROR "  Please install suggested packages:   sudo apt-get install ${MISSING_UBUNTU_PACKAGES_STR}   and try again.")
endif()
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
set(LIBRARIES ${LIBRARIES} dl)
set(LIBRARIES ${LIBRARIES} pthread)
set(LIBRARIES ${LIBRARIES} rt)
set(LIBRARIES ${LIBRARIES} m)
set(LIBRARIES ${LIBRARIES} crypt)
message(STATUS "Libraries: ${LIBRARIES}")
# ------------------------------------------------------------------------------
# Optional flags
# ------------------------------------------------------------------------------
if (DEBUG_MODE)
    add_definitions(-O0 -g3)
else()
    add_definitions(-O2)
endif()
if (BUILD_SYMBOLS)
    add_definitions(-g3)
endif()
# ------------------------------------------------------------------------------
# Build is2
# ------------------------------------------------------------------------------
include(ExternalProject)
if (BUILD_APPS)
  ExternalProject_Add(submodule_is2
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/sub/is2
    INSTALL_COMMAND ""
  )
endif()
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
# make the cmake list variables into .deb-compatible strings
string(REPLACE ";" ", " CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS_LIST}")
string(REPLACE ";" ", " CPACK_DEBIAN_PACKAGE_BUILDS_DEPENDS "${CPACK_DEBIAN_PACKAGE_BUILDS_DEPENDS_LIST}")
# ------------------------------------------------------------------------------
# Version
# ------------------------------------------------------------------------------
EXECUTE_PROCESS(COMMAND git describe --tags OUTPUT_VARIABLE VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
# TODO removing requirement for now
#if(NOT ${VERSION} MATCHES ^[0-9]+.[0-9]+)
#        message(FATAL_ERROR "Most recent tag '${VERSION}' does not match required version regex: ^[0-9]+.[0-9]+
#Does it start with a number?")
#endif()
add_definitions(-DWAFLZ_VERSION="${VERSION}")
# ------------------------------------------------------------------------------
# Debian Package Support
# ------------------------------------------------------------------------------
EXECUTE_PROCESS(COMMAND lsb_release -cs OUTPUT_VARIABLE DISTRIBUTION OUTPUT_STRIP_TRAILING_WHITESPACE)
SET(CPACK_GENERATOR "DEB")
SET(CPACK_DEBIAN_PACKAGE_VERSION "${VERSION}-${DISTRIBUTION}")
SET(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
SET(CPACK_PACKAGE_FILE_NAME "waflz_${CPACK_DEBIAN_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}")
SET(CPACK_DEBIAN_PACKAGE_NAME "waflz")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Reed Morrison")
SET(CPACK_DEBIAN_PACKAGE_DEPENDS "python-protobuf, libprotobuf-dev (>= 2.1.0-1), protobuf-compiler (>= 2.1.0-1), python-protobuf")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Waflz Libraries and tools")
SET(CPACK_PACKAGE_DESCRIPTION "Waflz Libraries and tools")
message(STATUS "Package Configuration:")
message("")
message("    Option                                     Value                     ")
message("    ---------------------------------------------------------------------")
message("    Package Version:                           ${CPACK_DEBIAN_PACKAGE_VERSION}")
message("")
INCLUDE(CPack)
# ------------------------------------------------------------------------------
# include source/test directories
# ------------------------------------------------------------------------------
add_subdirectory(proto)
add_subdirectory(src)
if (BUILD_APPS)
  add_subdirectory(util)
endif()
if (BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
