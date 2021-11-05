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
#include "op/byte_range.h"
#include "support/ndebug.h"
#include <string.h>
//! ----------------------------------------------------------------------------
//! byte_range test
//! ----------------------------------------------------------------------------
TEST_CASE( "byte_range basic test", "[byte_range_basic]" ) {
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("basic init/match") {
                ns_waflz::byte_range *l_br = NULL;
                l_br = new ns_waflz::byte_range();
                REQUIRE((l_br != NULL));
                // -----------------------------------------
                // clean up
                // -----------------------------------------
                if(l_br)
                {
                        delete l_br;
                        l_br = NULL;
                }
        }
}
