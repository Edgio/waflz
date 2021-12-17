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
add_test(blackbox_profile         ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/profile/test_bb_profile.py)
add_test(blackbox_wjc             ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/wjc/test_bb_wjc.py)
add_test(blackbox_challenge       ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/challenge/test_bb_challenge.py)
add_test(blackbox_scopes          ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/scopes/test_bb_scopes.py)
add_test(blackbox_scopes_updates  ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/scopes/test_bb_scopes_updates.py)
add_test(blackbox_limit_lmdb      ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/limit/test_bb_limit_lmdb.py)
add_test(blackbox_limit           ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/limit/test_bb_limit.py)
# ------------------------------------------------------------------------------
# tests
# ------------------------------------------------------------------------------
add_custom_target(blackbox
  ${CMAKE_SOURCE_DIR}/tests/blackbox/run_tests.sh
  DEPENDS blackbox
)
