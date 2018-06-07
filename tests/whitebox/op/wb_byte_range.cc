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
#include "op/byte_range.h"
#include "support/ndebug.h"
#include <string.h>
//: ----------------------------------------------------------------------------
//: byte_range test
//: ----------------------------------------------------------------------------
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
