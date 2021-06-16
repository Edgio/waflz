# ------------------------------------------------------------------------------
# macros
# ------------------------------------------------------------------------------
macro (add_waflz_wb_test test_name)
    # SET(SRCS wb_matched_data.cc)
    add_executable("wb_${test_name}" "wb_${test_name}.cc")
    target_link_libraries("wb_${test_name}" ${DEBUG_LIBRARIES} waflz_compiled_catch waflzcore ${LIBRARIES})
    add_test(${test_name} "wb_${test_name}")
endmacro()
# ------------------------------------------------------------------------------
# build catch
# ------------------------------------------------------------------------------
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ../../ext/)
add_library(waflz_compiled_catch STATIC ${CMAKE_CURRENT_SOURCE_DIR}/../../ext/catch/catch.hpp _catch.cc)
# ------------------------------------------------------------------------------
# build tests
# ------------------------------------------------------------------------------
add_subdirectory(support)
add_subdirectory(jspb)
add_subdirectory(core)
add_subdirectory(op)
add_subdirectory(parser)
add_subdirectory(db)
add_subdirectory(limit)
