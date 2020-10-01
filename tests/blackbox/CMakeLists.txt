# ----------------------------------------------------------------------------
# Copyright (C) 2017 Verizon.  All Rights Reserved.
# All Rights Reserved
#
#   Author: Raymond Mintz
#   Date:   01/19/2016
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
# Project setup
project(waflz)
cmake_minimum_required(VERSION 3.5)
# ------------------------------------------------------------------------------
# Resolve dependencies
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# Look for required python files
# ------------------------------------------------------------------------------
# TODO: use FindPython (available 3.12) - https://cmake.org/cmake/help/latest/module/FindPython.html
# find_python_module(pytest REQUIRED)
# find_python_module(requests REQUIRED)
# ------------------------------------------------------------------------------
# waflz
# ------------------------------------------------------------------------------
add_test(blackbox_acl             ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/acl/test_bb_acl.py)
add_test(blackbox_acl_accesslists ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/acl/test_bb_acl_accesslists.py)
add_test(blackbox_ruleset         ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/ruleset/test_ruleset.py)
add_test(blackbox_rules           ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/rules/test_bb_rules.py)
add_test(blackbox_rtu             ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/rules/test_bb_rtu.py)
add_test(blackbox_instances       ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/instances/test_instances.py)
add_test(blackbox_profile         ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/profile/test_bb_profile.py)
add_test(blackbox_wjc             ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/wjc/test_bb_wjc.py)
add_test(blackbox_bot             ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/bot_challenge/test_bb_bot_challenge.py)
if (BUILD_RATE_LIMITING)
add_test(blackbox_scopes          ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/scopes/test_bb_scopes.py)
add_test(blackbox_scopes_updates  ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/scopes/test_bb_scopes_updates.py)
endif()
# ------------------------------------------------------------------------------
# tests
# ------------------------------------------------------------------------------
add_custom_target(blackbox
  ${CMAKE_SOURCE_DIR}/tests/blackbox/run_tests.sh
  DEPENDS blackbox
)
