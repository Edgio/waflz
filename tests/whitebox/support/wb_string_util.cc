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
#include "waflz/string_util.h"
#include <string>
#include <string.h>
//! ----------------------------------------------------------------------------
//! convert_hex_to_uint
//! ----------------------------------------------------------------------------
TEST_CASE( "convert hex to uint", "[convert_hex_to_uint]" ) {

        SECTION("Verify basic") {
                int32_t l_s = 0;
                uint64_t l_id = 0;
                l_s = ns_waflz::convert_hex_to_uint(l_id, "DEADDEAD");
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_id == 3735936685));
                l_s = ns_waflz::convert_hex_to_uint(l_id, "0050");
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_id == 80));
        }
        SECTION("Verify failures") {
                int32_t l_s = 0;
                uint64_t l_id = 0;
                l_s = ns_waflz::convert_hex_to_uint(l_id, "RAT00DEADFART");
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
        }
}
