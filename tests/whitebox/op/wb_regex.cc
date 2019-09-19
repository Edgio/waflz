//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    TODO.cc
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
#include "op/regex.h"
#include "support/ndebug.h"
#include "support/time_util.h"
#define REGEX_PREFIX "bananas*"
#define REGEX_IP_ADDRESS "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"
//: ----------------------------------------------------------------------------
//: pcre obj
//: ----------------------------------------------------------------------------
TEST_CASE( "pcre obj test", "[regex]" ) {
        SECTION("validate ip address match") {
                ns_waflz::regex l_p;
                int32_t l_s;
                l_s = l_p.init(REGEX_IP_ADDRESS, strlen(REGEX_IP_ADDRESS));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                int l_compare;
                l_compare = l_p.compare("127.0.0.1", strlen("127.0.0.1"));
                REQUIRE((l_compare > 0));
                l_compare = l_p.compare("they don't think it be like it is, but it do",
                                 strlen("they don't think it be like it is, but it do"));
                REQUIRE((l_compare <= 0));
        }
        SECTION("validate prefix") {
                ns_waflz::regex l_p;
                int32_t l_s;
                l_s = l_p.init(REGEX_PREFIX, strlen(REGEX_PREFIX));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                int l_compare;
                l_compare = l_p.compare("bananas are really cool", strlen("bananas are really cool"));
                REQUIRE((l_compare > 0));
                l_compare = l_p.compare("monkeys aint cool", strlen("monkeys aint cool"));
                REQUIRE((l_compare <= 0));
        }
        SECTION("reDoS test") {
                ns_waflz::regex l_p;
                int32_t l_s;
#define _STR "^((ab)*)+$"
#define _MATCH "ababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab a"
                l_s = l_p.init(_STR, strlen(_STR));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                uint64_t l_t_s;
                l_t_s = ns_waflz::get_time_ms();
                for(int i = 0; i < 10; ++i)
                {
                int l_m;
                ns_waflz::data_list_t l_d;
                l_m = l_p.compare_all(_MATCH, strlen(_MATCH), &l_d);
                REQUIRE((l_m <= 0));
                }
                uint64_t l_dt_s;
                l_dt_s = ns_waflz::get_delta_time_ms(l_t_s);
                REQUIRE(l_dt_s < 200);
        }
}
