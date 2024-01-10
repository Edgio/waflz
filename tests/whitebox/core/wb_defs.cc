//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! Includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
//! ----------------------------------------------------------------------------
//!                     data_map_t tests
//! ----------------------------------------------------------------------------
TEST_CASE( "valid_data_t_map_compare", "[test]" ) {
        SECTION("build map") {
                // -----------------------------------------
                // create data_map_t
                // -----------------------------------------
                ns_waflz::data_unordered_map_t l_data_map;
                // -----------------------------------------
                // add 1 entry
                // -----------------------------------------
                ns_waflz::data_t l_key_1;
                l_key_1.m_data = "key_1";
                l_key_1.m_len = 5;
                ns_waflz::data_t l_entry_1;
                l_entry_1.m_data = "entry_1";
                l_entry_1.m_len = 7;
                l_data_map[l_key_1] = l_entry_1;
                // -----------------------------------------
                // assert entry in list with value
                // and list size 1
                // -----------------------------------------
                ns_waflz::data_unordered_map_t::const_iterator l_header = l_data_map.find(l_key_1);
                REQUIRE(l_data_map.size() == 1);
                REQUIRE((l_header != l_data_map.end()));
                REQUIRE(strncasecmp(l_header->first.m_data, "key_1", l_header->first.m_len) == 0);
                REQUIRE(strncasecmp(l_header->second.m_data, "entry_1", l_header->second.m_len) == 0);
                // -----------------------------------------
                // add 2nd entry
                // -----------------------------------------
                ns_waflz::data_t l_key_2;
                l_key_2.m_data = "key_2";
                l_key_2.m_len = 5;
                ns_waflz::data_t l_entry_2;
                l_entry_2.m_data = "entry_2";
                l_entry_2.m_len = 7;
                l_data_map[l_key_2] = l_entry_2;
                // -----------------------------------------
                // assert new entry in list with value
                // -----------------------------------------
                l_header = l_data_map.find(l_key_2);
                REQUIRE(l_data_map.size() == 2);
                REQUIRE((l_header != l_data_map.end()));
                REQUIRE(strncasecmp(l_header->first.m_data, "key_2", l_header->first.m_len) == 0);
                REQUIRE(strncasecmp(l_header->second.m_data, "entry_2", l_header->second.m_len) == 0);
                // -----------------------------------------
                // add 3rd entry
                // -----------------------------------------
                ns_waflz::data_t l_key_3;
                l_key_3.m_data = "key_1_big";
                l_key_3.m_len = 9;
                ns_waflz::data_t l_entry_3;
                l_entry_3.m_data = "entry_3";
                l_entry_3.m_len = 7;
                l_data_map[l_key_3] = l_entry_3;
                // -----------------------------------------
                // assert new entry in list with value
                // -----------------------------------------
                l_header = l_data_map.find(l_key_3);
                REQUIRE(l_data_map.size() == 3);
                REQUIRE((l_header != l_data_map.end()));
                REQUIRE(strncasecmp(l_header->first.m_data, "key_1_big", l_header->first.m_len) == 0);
                REQUIRE(strncasecmp(l_header->second.m_data, "entry_3", l_header->second.m_len) == 0);
                // -----------------------------------------
                // add 4rd entry - should just update
                // because case insensitive
                // -----------------------------------------
                ns_waflz::data_t l_key_4;
                l_key_4.m_data = "KEY_1";
                l_key_4.m_len = 5;
                ns_waflz::data_t l_entry_4;
                l_entry_4.m_data = "entry_4";
                l_entry_4.m_len = 7;
                l_data_map[l_key_4] = l_entry_4;
                // -----------------------------------------
                // assert new entry in list with value
                // -----------------------------------------
                l_header = l_data_map.find(l_key_4);
                REQUIRE(l_data_map.size() == 3);
                REQUIRE((l_header != l_data_map.end()));
                REQUIRE(strncasecmp(l_header->first.m_data, "key_1", l_header->first.m_len) == 0);
                REQUIRE(strncasecmp(l_header->second.m_data, "entry_4", l_header->second.m_len) == 0);
        }
}