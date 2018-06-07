//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_byte_range.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    04/30/2018
//:
//:   Licensed under the Apache License, Version 2.0 (the "License");
//:   you may not use this file except in compliance with the License.
//:   You may obtain a copy of the License at
//:
//:       http://www.apache.org/licenses/LICENSE-2.0
//:
//:   Unless required by applicable law or agreed to in writing, software
//:   distributed under the License is distributed on an "AS IS" BASIS,
//:   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//:   See the License for the specific language governing permissions and
//:   limitations under the License.
//:
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "op/luhn.h"
#include "support/ndebug.h"
#include <string.h>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define CC_N_INVALID_0  "9999-9999-9999-9999"
#define CC_N_INVALID_1  "hi i am a monkey"
#define CC_N_VALID_VISA "4532-8622-7821-8872"
//: ----------------------------------------------------------------------------
//: byte_range test
//: ----------------------------------------------------------------------------
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
