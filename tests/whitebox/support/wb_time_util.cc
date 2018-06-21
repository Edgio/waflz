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
#include "support/time_util.h"
#include <unistd.h>
#include <stdio.h>
//: ----------------------------------------------------------------------------
//: time_util
//: ----------------------------------------------------------------------------
TEST_CASE( "time util test", "[time_util]" ) {

        SECTION("validate time caching") {
                uint64_t l_cur_time_ms;
                uint64_t l_nxt_time_ms;

                ns_waflz::time_set_max_resolution_us(100000);

                // Verify same time after sleep
                l_cur_time_ms = ns_waflz::get_time_ms();
                usleep(1100);
                l_nxt_time_ms = ns_waflz::get_time_ms();
                REQUIRE((l_cur_time_ms == l_nxt_time_ms));
                l_cur_time_ms = ns_waflz::get_time_ms();
                usleep(1100);
                l_nxt_time_ms = ns_waflz::get_time_ms();
                REQUIRE((l_cur_time_ms == l_nxt_time_ms));

                ns_waflz::time_set_max_resolution_us(1000);
                l_cur_time_ms = ns_waflz::get_time_ms();
                l_cur_time_ms = ns_waflz::get_time_ms();

                // Verify diff time after sleep
                l_cur_time_ms = ns_waflz::get_time_ms();
                usleep(1100);
                l_nxt_time_ms = ns_waflz::get_time_ms();
                REQUIRE((l_cur_time_ms != l_nxt_time_ms));
                l_cur_time_ms = ns_waflz::get_time_ms();
                usleep(1100);
                l_nxt_time_ms = ns_waflz::get_time_ms();
                REQUIRE((l_cur_time_ms != l_nxt_time_ms));
        }
        SECTION("validate time delta") {
                uint64_t l_cur_time_ms;
                uint64_t l_nxt_time_ms;
                ns_waflz::time_set_max_resolution_us(1000);
                l_cur_time_ms = ns_waflz::get_time_ms();
                usleep(3000);
                l_nxt_time_ms = ns_waflz::get_delta_time_ms(l_cur_time_ms);
                printf("l_nxt_time: %lu\n", l_nxt_time_ms);
                REQUIRE((l_nxt_time_ms >= 3));
                REQUIRE((l_nxt_time_ms < 8));

                l_cur_time_ms = ns_waflz::get_time_ms();
                usleep(5000);
                l_nxt_time_ms = ns_waflz::get_delta_time_ms(l_cur_time_ms);
                printf("l_nxt_time: %lu\n", l_nxt_time_ms);
                REQUIRE((l_nxt_time_ms >= 5));
                REQUIRE((l_nxt_time_ms < 10));
        }
        SECTION("validate time string to epoch") {
                std::string l_time_string("2016-07-20T00:44:20.744583Z");
                std::string l_format("%Y-%m-%dT%H:%M:%S%Z");
                uint64_t l_epoch1 = ns_waflz::get_epoch_seconds(l_time_string.c_str(), l_format.c_str());
                //increasing one min
                l_time_string.assign("2016-07-20T00:45:20.744583Z");
                uint64_t l_epoch2 = ns_waflz::get_epoch_seconds(l_time_string.c_str(), l_format.c_str());
                //increasing one sec
                l_time_string.assign("2016-07-20T00:45:21.744583Z");
                uint64_t l_epoch3 = ns_waflz::get_epoch_seconds(l_time_string.c_str(), l_format.c_str());
                //increasing year,month,date
                l_time_string.assign("2018-04-10T00:45:20.744583Z");
                uint64_t l_epoch4 = ns_waflz::get_epoch_seconds(l_time_string.c_str(), l_format.c_str());
                REQUIRE((l_epoch2 > l_epoch1));
                REQUIRE((l_epoch3 > l_epoch2));
                REQUIRE((l_epoch4 > l_epoch3));
                //assign wrong format -check whether result is zero
                l_time_string.assign("2018-04-10T00:45:30.744583Z");
                l_format.assign("%d-%m-%YT%s:%M:%H.%fZ");
                uint64_t l_epoch = ns_waflz::get_epoch_seconds(l_time_string.c_str(), l_format.c_str());
                REQUIRE((l_epoch == 0));
        }
}
