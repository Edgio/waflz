//! ----------------------------------------------------------------------------
//! Copyright Verizon.
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
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "support/time_util.h"
#include <unistd.h>
#include <stdio.h>
//! ----------------------------------------------------------------------------
//! time_util
//! ----------------------------------------------------------------------------
TEST_CASE( "time util test", "[time_util]" ) {
#if !defined(__APPLE__) && !defined(__darwin__)
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
                printf("l_nxt_time: %" PRIu64 "\n", l_nxt_time_ms);
                REQUIRE((l_nxt_time_ms >= 3));
                REQUIRE((l_nxt_time_ms < 8));
                l_cur_time_ms = ns_waflz::get_time_ms();
                usleep(5000);
                l_nxt_time_ms = ns_waflz::get_delta_time_ms(l_cur_time_ms);
                printf("l_nxt_time: %" PRIu64 "\n", l_nxt_time_ms);
                REQUIRE((l_nxt_time_ms >= 5));
                REQUIRE((l_nxt_time_ms < 10));
        }
#endif
        SECTION("validate time string to epoch") {
                std::string l_time_string("2016-07-20T00:44:20.744583Z");
                std::string l_format(CONFIG_DATE_FORMAT);
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
