//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_lm_db.cc
//: \details: TODO
//: \author:  Revathi Sabanayagam
//: \date:    11/02/2020
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
//: includes
//: ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "waflz/lm_db.h"
#include "support/time_util.h"
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define MONKEY_KEY "TEST::KEY::MONKEY::BONGO"
#define BANANA_KEY "TEST::KEY::BANANA::SMELLY"
#define TEST_KEY "TEST::KEY::TEST::NONE"
//: ----------------------------------------------------------------------------
//: remove dir
//: ----------------------------------------------------------------------------
static int remove_dir(const std::string& a_db_dir)
{
        int32_t l_s;
        struct stat l_stat;
        l_s = stat(a_db_dir.c_str(), &l_stat);
        if(l_s != 0)
        {
                return 0;
        }
        std::string l_file1(a_db_dir), l_file2(a_db_dir);
        l_file1.append("/data.mdb");
        l_file2.append("/lock.mdb");
        unlink(l_file1.c_str());
        unlink(l_file2.c_str());
        l_s = rmdir(a_db_dir.c_str());
        if(l_s != 0)
        {
                return -1;
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: mkdir
//: ----------------------------------------------------------------------------
static int create_dir(const std::string& a_db_dir)
{
        struct stat l_stat;
        int32_t l_s;
        l_s = remove_dir(a_db_dir);
        if(l_s != 0)
        {
                return -1;
        }
        l_s = mkdir(a_db_dir.c_str(), 0700);
        return l_s;
}

//:---------------------------------------------------------------------------
//: lm_db
//: ----------------------------------------------------------------------------
TEST_CASE( "lmdb test", "[lmdb]" ) {
        SECTION("validate bad init") {
                int32_t l_s;
                ns_waflz::lm_db l_db;
                REQUIRE((l_db.get_init() == false));
                const char l_bad_db_dir[] = "/fish/fish/fish";
                l_s = l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, l_bad_db_dir, strlen(l_bad_db_dir));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_db.init();
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
        }
        SECTION("validate good init") {
                int32_t l_s;
                ns_waflz::lm_db l_db;
                REQUIRE((l_db.get_init() == false));
                std::string l_db_dir("/tmp/test_lmdb");
                l_s = create_dir(l_db_dir);
                REQUIRE((l_s == 0));
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, l_db_dir.c_str(), l_db_dir.length());
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_READERS, NULL, 6);
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_MMAP_SIZE, NULL, 10485760);
                l_s = l_db.init();
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_db.get_init() == true);
                l_s = remove_dir(l_db_dir);
                REQUIRE((l_s == 0));
        }
        SECTION("validate increment key and expiration") {
            int32_t l_s;
            ns_waflz::lm_db l_db;
            REQUIRE((l_db.get_init() == false));
            std::string l_db_dir("/tmp/test_lmdb");
            l_s = create_dir(l_db_dir);
            REQUIRE((l_s == 0));
            l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, l_db_dir.c_str(), l_db_dir.length());
            l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_READERS, NULL, 6);
            l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_MMAP_SIZE, NULL, 10485760);
            l_s = l_db.init();
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            REQUIRE(l_db.get_init() == true);
            int64_t l_result;
            l_s = l_db.increment_key(l_result, MONKEY_KEY, 2000);
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            REQUIRE(l_result == 1);
            l_s = l_db.increment_key(l_result, MONKEY_KEY, 2000);
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            REQUIRE(l_result == 2);
            l_s = l_db.increment_key(l_result, BANANA_KEY, 4000);
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            REQUIRE(l_result == 1);
            l_s = l_db.increment_key(l_result, BANANA_KEY, 4000);
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            REQUIRE(l_result == 2);
            //sleep for 2 seconds, monkey key should have been expired
            usleep(2000000);
            //increment the test key, this should have cleared monkey key
            l_s = l_db.increment_key(l_result, TEST_KEY, 1000);
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            l_s = l_db.get_key(l_result, MONKEY_KEY, strlen(MONKEY_KEY));
            REQUIRE(l_s == WAFLZ_STATUS_ERROR);
            l_s = l_db.get_key(l_result, BANANA_KEY, strlen(BANANA_KEY));
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            REQUIRE(l_result == 2);
            //sleep for 2 more seconds, banana key should have been expired
            usleep(2000000);
            //increment the test key, this should have cleared banana key
            l_s = l_db.increment_key(l_result, TEST_KEY, 1000);
            l_s = l_db.get_key(l_result, BANANA_KEY, strlen(BANANA_KEY));
            REQUIRE(l_s == WAFLZ_STATUS_ERROR);
            //increment the keys again to check value resets to 1.
            l_s = l_db.increment_key(l_result, MONKEY_KEY, 1000);
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            REQUIRE(l_result == 1);
            l_s = l_db.increment_key(l_result, BANANA_KEY, 1000);
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            REQUIRE(l_result == 1);
            l_s = remove_dir(l_db_dir);
            REQUIRE(l_s == 0);
        }
        SECTION("validate sweep db - test if sweeping deletes expired keys from db") {
            int32_t l_s;
            ns_waflz::lm_db l_db;
            REQUIRE((l_db.get_init() == false));
            std::string l_db_dir("/tmp/test_lmdb");
            l_s = create_dir(l_db_dir);
            REQUIRE((l_s == 0));
            l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, l_db_dir.c_str(), l_db_dir.length());
            l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_READERS, NULL, 6);
            l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_MMAP_SIZE, NULL, 10485760);
            l_s = l_db.init();
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            REQUIRE(l_db.get_init() == true);
            int64_t l_result;
            l_s = l_db.increment_key(l_result, MONKEY_KEY, 4000);
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            REQUIRE(l_result == 1);
            l_s = l_db.increment_key(l_result, BANANA_KEY, 5000);
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            REQUIRE(l_result == 1);
            // sweep db 
            l_s = l_db.sweep_db();
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            int64_t l_out_val = -1;
            //verify sweep db didn't delete keys before expiry
            l_s = l_db.get_key(l_out_val, MONKEY_KEY, strlen(MONKEY_KEY));
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            REQUIRE(l_out_val == 1);
            l_s = l_db.get_key(l_out_val, BANANA_KEY, strlen(BANANA_KEY));
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            REQUIRE(l_out_val == 1);
            // sleep for 4 seconds and sweep db.Monkey key should have been
            //deleted
            sleep(4);
            l_s = l_db.sweep_db();
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            l_s = l_db.get_key(l_out_val, MONKEY_KEY, strlen(MONKEY_KEY));
            REQUIRE(l_s == WAFLZ_STATUS_ERROR);
            l_s = l_db.get_key(l_out_val, BANANA_KEY, strlen(BANANA_KEY));
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            sleep(1);
            l_s = l_db.sweep_db();
            REQUIRE(l_s == WAFLZ_STATUS_OK);
            l_s = l_db.get_key(l_out_val, BANANA_KEY, strlen(BANANA_KEY));
            REQUIRE(l_s == WAFLZ_STATUS_ERROR);
        }
}

