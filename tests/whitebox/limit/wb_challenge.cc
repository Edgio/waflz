//! ----------------------------------------------------------------------------
//! Copyright (C) 2018 Verizon.  All Rights Reserved.
//! All Rights Reserved
///
//! \file:    wb_challenge.cc
//! \details: TODO
//! \author:  Revathi Sabanayagam
//! \date:    01/06/2018
///
//!   Licensed under the Apache License, Version 2.0 (the "License");
//!   you may not use this file except in compliance with the License.
//!   You may obtain a copy of the License at
///
//!       http://www.apache.org/licenses/LICENSE-2.0
///
//!   Unless required by applicable law or agreed to in writing, software
//!   distributed under the License is distributed on an "AS IS" BASIS,
//!   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//!   See the License for the specific language governing permissions and
//!   limitations under the License.
///
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! Includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "waflz/challenge.h"
#include "waflz/rqst_ctx.h"
#include "waflz/string_util.h"
#include "support/base64.h"
#include "support/ndebug.h"
#include "limit.pb.h"
#include <string.h>
#include <stdint.h>
#include <unistd.h>
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
#define VALID_CHALLENGE_JSON "{"\
    "\"problems\": ["\
        "{"\
        "\"id\" : 1,"\
        "\"answer\" : \"100\","\
        "\"response_body_base64\" : \"some random base64 encoded html string1\""\
        "},"\
        "{"\
        "\"id\" : 2,"\
        "\"answer\" : \"200\","\
        "\"response_body_base64\" : \"some random base64 encoded html string2\""\
        "},"\
        "{"\
        "\"id\" : 3,"\
        "\"answer\" : \"300\","\
        "\"response_body_base64\" : \"some random base64 encoded html string3\""\
        "}"\
    "]"\
"}"
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
#define NO_ID_CHALLENGE_JSON "{"\
    "\"problems\": ["\
        "{"\
        "\"id\" : 1,"\
        "\"answer\" : \"100\","\
        "\"response_body_base64\" : \"some random base64 encoded html string\""\
        "},"\
        "{"\
        "\"answer\" : \"100\","\
        "\"response_body_base64\" : \"some random base64 encoded html string\""\
        "}"\
    "]"\
"}"
//! ----------------------------------------------------------------------------
//!                     LOAD CHALLENGE TESTS
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! load valid challenge test
//! ----------------------------------------------------------------------------
TEST_CASE( "valid_challenge_test", "[load_valid_challenge]" ) {
        SECTION("Verify challenge") {
                int32_t l_s;
                ns_waflz::challenge l_ch;
                l_s = l_ch.load(VALID_CHALLENGE_JSON, sizeof(VALID_CHALLENGE_JSON));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
        }
}
//! ----------------------------------------------------------------------------
//! load no id challenge test
//! ----------------------------------------------------------------------------
TEST_CASE( "no id challenge test", "[no id challenge test]") {
        SECTION("Verify no id challenge") {
                int32_t l_s;
                ns_waflz::challenge l_ch;
                l_s = l_ch.load(NO_ID_CHALLENGE_JSON, sizeof(NO_ID_CHALLENGE_JSON));
                REQUIRE(l_s == WAFLZ_STATUS_ERROR);
        }
}
//! ----------------------------------------------------------------------------
//! test maps
//! ----------------------------------------------------------------------------
TEST_CASE( "test maps", "[test maps]") {
        SECTION("Verify prob/answer/challenge in map") {
                int32_t l_s;
                ns_waflz::challenge l_ch;
                int32_t l_id;
                l_id = l_ch.get_rand_id();
                REQUIRE(l_id == WAFLZ_STATUS_ERROR);
                l_s = l_ch.load(VALID_CHALLENGE_JSON, sizeof(VALID_CHALLENGE_JSON));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // setup ctx
                // -----------------------------------------
                ns_waflz::rqst_ctx l_ctx(NULL, 0, NULL);
                // -----------------------------------------
                // verify challenge string
                // -----------------------------------------
                const std::string *l_cs = NULL;
                l_s = l_ch.get_challenge(&l_cs, 2, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((*l_cs == "some random base64 encoded html string2"));
        }	
}
//! ----------------------------------------------------------------------------
//! test ectoken
//! ----------------------------------------------------------------------------
TEST_CASE("test ectoken", "[test ectoken]") {
        SECTION("test ectoken") {
                int32_t l_s;
                ns_waflz::challenge l_ch;
                l_s = l_ch.load(VALID_CHALLENGE_JSON, sizeof(VALID_CHALLENGE_JSON));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // setup ctx
                // -----------------------------------------
                ns_waflz::rqst_ctx l_ctx(NULL, 0, NULL);
                l_ctx.m_src_addr.m_data = "1.1.1.1";
                l_ctx.m_src_addr.m_len = sizeof(l_ctx.m_src_addr.m_data);
                ns_waflz::data_t l_ua;
                l_ua.m_data = "User-Agent";
                l_ua.m_len = strlen(l_ua.m_data);
                ns_waflz::data_t l_ua_chrome;
                l_ua_chrome.m_data = "chrome";
                l_ua_chrome.m_len = strlen(l_ua_chrome.m_data);
                l_ctx.m_header_map[l_ua] = l_ua_chrome;
                l_ch.set_ectoken(200, &l_ctx);
                ns_waflz::data_t l_k;
                ns_waflz::data_t l_v;
                l_ctx.m_cookie_map.clear();
                // -----------------------------------------
                // ec_secure
                // -----------------------------------------
                l_k.m_data = "ec_secure";
                l_k.m_len = sizeof("ec_secure") - 1;
                l_v.m_data = l_ctx.m_token.m_data;
                l_v.m_len = l_ctx.m_token.m_len;
                l_ctx.m_cookie_map[l_k] = l_v;
                // -----------------------------------------
                // ec_answer
                // -----------------------------------------
                l_k.m_data = "ec_answer";
                l_k.m_len = sizeof("ec_answer") - 1;
                l_v.m_data = "2";
                l_v.m_len = sizeof("2") - 1;
                l_ctx.m_cookie_map[l_k] = l_v;
                // -----------------------------------------
                // check token...
                // -----------------------------------------
                bool l_pass;
                l_s = l_ch.verify(l_pass, 60, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_pass == true));
                // -----------------------------------------
                // check token -expired...
                // -----------------------------------------
                l_s = l_ch.verify(l_pass, 0, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_pass == false));
                //NDBG_PRINT("err: %s\n", l_ch.get_err_msg());
                // -----------------------------------------
                // wang ip
                // -----------------------------------------
                l_ctx.m_src_addr.m_data = "1.1.1.2";
                l_ctx.m_src_addr.m_len = sizeof(l_ctx.m_src_addr.m_data);
                l_s = l_ch.verify(l_pass, 60, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_pass == false));
                //NDBG_PRINT("err: %s\n", l_ch.get_err_msg());
                // put back
                l_ctx.m_src_addr.m_data = "1.1.1.1";
                l_ctx.m_src_addr.m_len = sizeof(l_ctx.m_src_addr.m_data);
                // -----------------------------------------
                // wang user-agent
                // -----------------------------------------
                ns_waflz::data_t l_ua_fastly;
                l_ua_fastly.m_data = "fastly";
                l_ua_fastly.m_len = strlen(l_ua_fastly.m_data);
                l_ctx.m_header_map[l_ua] = l_ua_fastly;
                l_s = l_ch.verify(l_pass, 60, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_pass == false));
                //NDBG_PRINT("err: %s\n", l_ch.get_err_msg());
                // put back
                l_ctx.m_header_map[l_ua] = l_ua_chrome;
                // -----------------------------------------
                // wang answer
                // -----------------------------------------
                l_k.m_data = "ec_answer";
                l_k.m_len = sizeof("ec_answer") - 1;
                l_v.m_data = "monkeys";
                l_v.m_len = sizeof("monkeys") - 1;
                l_ctx.m_cookie_map[l_k] = l_v;
                l_s = l_ch.verify(l_pass, 60, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_pass == false));
                //NDBG_PRINT("err: %s\n", l_ch.get_err_msg());
        }
}
