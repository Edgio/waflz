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
//! includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "waflz/kycb_db.h"
#include "support/time_util.h"
#include <unistd.h>
#include <string.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define MONKEY_KEY "TEST::KEY::MONKEY::BONGO"
#define BANANA_KEY "TEST::KEY::BANANA::SMELLY"
//! ----------------------------------------------------------------------------
//! kycb_db
//! ----------------------------------------------------------------------------
TEST_CASE( "kyoto cabinet db test", "[kycb_db]" ) {
        SECTION("validate bad init") {
                ns_waflz::kycb_db l_db;
                REQUIRE((l_db.get_init() == false));
                const char l_bad_db_file[] = "/fish/fish/fish/fish.db";
                int32_t l_s;
                l_s = l_db.set_opt(ns_waflz::kycb_db::OPT_KYCB_DB_FILE_PATH, l_bad_db_file, strlen(l_bad_db_file));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_db.init();
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
                //printf("error: %s\n", l_db.get_err_msg());
        }
        SECTION("validate good init") {
                ns_waflz::kycb_db l_db;
                REQUIRE((l_db.get_init() == false));
                int32_t l_s;
                char l_db_file[] = "/tmp/XXXXXX.kycb.db";
                l_s = mkstemp(l_db_file);
                unlink(l_db_file);
                l_s = l_db.set_opt(ns_waflz::kycb_db::OPT_KYCB_DB_FILE_PATH, l_db_file, strlen(l_db_file));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_db.init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                int64_t l_val;
                l_s = l_db.increment_key(l_val, MONKEY_KEY, 1000);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //printf("l_val: %ld\n", l_val);
                REQUIRE((l_val == 1));
                l_s = l_db.increment_key(l_val, MONKEY_KEY, 1000);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //printf("l_val: %ld\n", l_val);
                REQUIRE((l_val == 2));
                l_s = l_db.increment_key(l_val, BANANA_KEY, 1000);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //printf("l_val: %ld\n", l_val);
                REQUIRE((l_val == 1));
                l_s = l_db.increment_key(l_val, BANANA_KEY, 1000);
                l_s = l_db.increment_key(l_val, BANANA_KEY, 1000);
                //printf("PRINT ALL KEYS\n");
                //l_db.print_all_keys();
                l_s = l_db.get_key(l_val, MONKEY_KEY, strlen(MONKEY_KEY));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //printf("l_val: %ld\n", l_val);
                REQUIRE((l_val == 2));
                l_s = l_db.increment_key(l_val, MONKEY_KEY, 1000);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //printf("l_val: %ld\n", l_val);
                REQUIRE((l_val == 3));
                l_s = l_db.increment_key(l_val, BANANA_KEY, 1000);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //printf("l_val: %ld\n", l_val);
                REQUIRE((l_val == 4));
                //sprintf("error: %s\n", l_db.get_err_msg());
                // wait for monkey key to expire
                usleep(1100000);
                l_s = l_db.get_key(l_val, MONKEY_KEY, strlen(MONKEY_KEY));
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
                l_s = l_db.increment_key(l_val, MONKEY_KEY, 1000);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //printf("l_val: %ld\n", l_val);
                REQUIRE((l_val == 1));
                unlink(l_db_file);
        }
}
