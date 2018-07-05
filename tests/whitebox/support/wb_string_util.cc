//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_file_util.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    12/06/2016
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
#include "support/string_util.h"
#include <string>
#include <string.h>
//: ----------------------------------------------------------------------------
//: convert_hex_to_uint
//: ----------------------------------------------------------------------------
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
