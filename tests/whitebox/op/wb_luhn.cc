//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
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
#include "op/luhn.h"
#include "support/ndebug.h"
#include <string.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define CC_N_INVALID_0  "9999-9999-9999-9999"
#define CC_N_INVALID_1  "hi i am a monkey"
#define CC_N_VALID_VISA "4532-8622-7821-8872"
//! ----------------------------------------------------------------------------
//! byte_range test
//! ----------------------------------------------------------------------------
TEST_CASE( "luhn basic test", "[luhn_basic]" ) {
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("basic init/match") {
                bool l_m = false;
                l_m = ns_waflz::luhn_validate(CC_N_INVALID_0, strlen(CC_N_INVALID_0));
                REQUIRE((l_m == false));
                l_m = ns_waflz::luhn_validate(CC_N_INVALID_1, strlen(CC_N_INVALID_1));
                REQUIRE((l_m == false));
                l_m = ns_waflz::luhn_validate(CC_N_VALID_VISA, strlen(CC_N_VALID_VISA));
                REQUIRE((l_m == true));
        }
}
