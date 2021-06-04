include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_BINARY_DIR}
  ${CMAKE_BINARY_DIR}/proto
)
add_waflz_wb_test(lm_db)
# commenting out -requires redis to run...
#add_waflz_wb_test(redis_db)
