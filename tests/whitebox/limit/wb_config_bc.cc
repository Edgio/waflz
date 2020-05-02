//! ----------------------------------------------------------------------------
//! Copyright (C) 2016 Verizon.  All Rights Reserved.
//! All Rights Reserved
//:
//! \file:    wb_config.cc
//! \details: TODO
//! \author:  Reed P. Morrison
//! \date:    12/06/2016
//:
//!   Licensed under the Apache License, Version 2.0 (the "License");
//!   you may not use this file except in compliance with the License.
//!   You may obtain a copy of the License at
//:
//!       http://www.apache.org/licenses/LICENSE-2.0
//:
//!   Unless required by applicable law or agreed to in writing, software
//!   distributed under the License is distributed on an "AS IS" BASIS,
//!   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//!   See the License for the specific language governing permissions and
//!   limitations under the License.
//:
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "jspb/jspb.h"
#include "support/time_util.h"
#include "support/string_util.h"
#include "support/ndebug.h"
#include "waflz/def.h"
#include "waflz/config.h"
#include "waflz/configs.h"
#include "waflz/challenge.h"
#include "waflz/kycb_db.h"
#include "waflz/rqst_ctx.h"
#include "waflz/geoip2_mmdb.h"
#include "limit.pb.h"
#include <string.h>
#include <unistd.h>
//:----------------------------------------------------------------------------
//! globals
//:----------------------------------------------------------------------------
static std::string g_ec_cookie_val = "";
//:----------------------------------------------------------------------------
//! token key for decryption
//:----------------------------------------------------------------------------
#define EC_TOKEN_KEY "A75C2978BAFAED25589A7017B8CF839D866F755A187DC579ABF30AFE696E8F30"
//! ----------------------------------------------------------------------------
//! config
//! ----------------------------------------------------------------------------
#define CONFIG_W_BROWSER_CHALLENGE_ENFORCEMENT_JSON \
"{"\
"  \"version\": 2,"\
"  \"id\": \"b9882f74-fdc0-4bcc-89ae-36c808e9497916715\","\
"  \"name\": \"name\","\
"  \"type\": \"CONFIG\","\
"  \"customer_id\": \"16715\","\
"  \"enabled_date\": \"2016-07-20T00:44:20.744583Z\","\
"  \"last_modified_date\": \"2016-08-25T00:45:20.744583Z\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"0A0c5799-78b1-470f-91af-f1c999be94cb16715\","\
"      \"name\": \"RULE_STUFF\","\
"      \"disabled\": false,"\
"      \"duration_sec\": 1,"\
"      \"num\": 5,"\
"      \"keys\": ["\
"        \"IP\""\
"      ],"\
"      \"action\": {"\
"        \"id\": \"28b3de98-b3e1-4642-ac77-50d2fe69fab416715\","\
"        \"name\": \"bc-enforcement\","\
"        \"type\": \"browser-challenge\","\
"        \"duration_sec\": 3,"\
"        \"enf_type\": \"BROWSER_CHALLENGE\","\
"        \"status\": 403,"\
"        \"valid_for_sec\": 1"\
"      },"\
"      \"scope\": {"\
"        \"host\": {"\
"          \"type\": \"GLOB\","\
"          \"value\": \"*.cats.*.com\","\
"          \"is_negated\": false"\
"        },"\
"        \"path\": {"\
"          \"type\": \"STREQ\","\
"          \"value\": \"/cats.html\","\
"          \"is_negated\": false"\
"        }"\
"      }"\
"    }"\
"  ]"\
"}"
//! ----------------------------------------------------------------------------
//! config
//! ----------------------------------------------------------------------------
#define CONFIG_W_ALWAYS_ON_MODE_BROWSER_CHALLENGE_JSON \
"{"\
"  \"version\": 2,"\
"  \"id\": \"b9882f74-fdc0-4bcc-89ae-36c808e9497916715\","\
"  \"name\": \"name\","\
"  \"type\": \"CONFIG\","\
"  \"customer_id\": \"16715\","\
"  \"enabled_date\": \"2016-07-20T00:44:20.744583Z\","\
"  \"last_modified_date\": \"2016-08-25T00:45:20.744583Z\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"0A0c5799-78b1-470f-91af-f1c999be94cb16715\","\
"      \"name\": \"RULE_STUFF\","\
"      \"disabled\": false,"\
"      \"duration_sec\": 1,"\
"      \"num\": 5,"\
"      \"keys\": ["\
"        \"IP\""\
"      ],"\
"      \"always_on\": true,"\
"      \"action\": {"\
"        \"id\": \"28b3de98-b3e1-4642-ac77-50d2fe69fab416715\","\
"        \"name\": \"bc-enforcement\","\
"        \"type\": \"browser-challenge\","\
"        \"duration_sec\": 10,"\
"        \"enf_type\": \"BROWSER_CHALLENGE\","\
"        \"status\": 403,"\
"        \"valid_for_sec\": 1"\
"      },"\
"      \"scope\": {"\
"        \"host\": {"\
"          \"type\": \"GLOB\","\
"          \"value\": \"*.cats.*.com\","\
"          \"is_negated\": false"\
"        },"\
"        \"path\": {"\
"          \"type\": \"STREQ\","\
"          \"value\": \"/cats.html\","\
"          \"is_negated\": false"\
"        }"\
"      }"\
"    }"\
"  ]"\
"}"
//! ----------------------------------------------------------------------------
//! sample challenge json
//! ----------------------------------------------------------------------------
#define VALID_CHALLENGE_JSON "{"\
    "\"problems\": ["\
          "{"\
              "\"id\" : 1,"\
              "\"answer\" : \"232\","\
              "\"response_body_base64\" : \"PCFET0NUWVBFIEhUTUw/PGh0bWwgbGFuZz0iZW4tVVMiPjxoZWFkPjx0aXRsZT5WYWxpZGF0aW5nIHlvdXIgYnJvd3NlcjwvdGl0bGU/PHNjcmlwdD5mdW5jdGlvbiBjaGFsbGVuZ2UoKXt2YXIgdmFsID0gMTIxKzExMTt2YXIgY2tzPSJlY19zZWN1cmU9e3tFQ19UT0tFTn19Ijtkb2N1bWVudC5jb29raWU9Y2tzO2NrYT0iZWNfYW5zd2VyPSIrdmFsO2RvY3VtZW50LmNvb2tpZT1ja2E7bG9jYXRpb24ucmVsb2FkKCk7fTwvc2NyaXB0PjwvaGVhZD88Ym9keSBvbmxvYWQ9ImNoYWxsZW5nZSgpIj88dGFibGUgd2lkdGg9IjEwMCUiIGhlaWdodD0iMTAwJSIgY2VsbHBhZGRpbmc9IjIwIj88dHI+PHRkIGFsaWduPSJjZW50ZXIiIHZhbGlnbj0ibWlkZGxlIj88ZGl2IGNsYXNzPSJicm93c2VyLXZlcmlmaWNhdGlvbiI+PG5vc2NyaXB0PjxoMSBkYXRhLXRyYW5zbGF0ZT0idHVybl9vbl9qcyIgc3R5bGU9ImNvbG9yOiNiZDI0MjY7Ij9QbGVhc2UgdHVybiBKYXZhU2NyaXB0IG9uIGFuZCByZWxvYWQgdGhlIHBhZ2UuPC9oMT88L25vc2NyaXB0PjwvZGl2PjwvdGQ+PC90cj88L3RhYmxlPjxoMT9WYWxpZGF0aW5nIHlvdXIgYnJvd3NlciE8L2gxPjwvYm9keT88L2h0bWw+\""\
          "}"\
      "]"\
"}"
//! ----------------------------------------------------------------------------
//! callbacks
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! get ip callback
//! ----------------------------------------------------------------------------
static int32_t get_rqst_ip_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_uri[] = "192.16.26.2";
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get uri callback
//! ----------------------------------------------------------------------------
static int32_t get_rqst_uri_cats_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_uri[] = "/cats.html";
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get uri callback
//! ----------------------------------------------------------------------------
static int32_t get_rqst_host_cats_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_uri[] = "www.cats.dogs.com";
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get header callbacks
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_bc_cb(uint32_t& a_val, void* a_ctx)
{
        a_val = 1;
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_header_w_idx_bc_cb
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_w_idx_bc_cb(const char **ao_key,
                                           uint32_t &ao_key_len,
                                           const char **ao_val,
                                           uint32_t &ao_val_len,
                                           void *a_ctx,
                                           uint32_t a_idx)
{
        *ao_key = "User-Agent";
        ao_key_len = strlen("User-Agent");
        *ao_val = "monkey";
        ao_val_len = strlen("monkey");
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_header_size_cb - size 2
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_2_bc_cb(uint32_t& a_val, void* a_ctx)
{
        a_val = 2;
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_header_w_idx_bc_cb - both ua and cookie
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_w_idx_bc_cookie_cb(const char **ao_key,
                                                  uint32_t &ao_key_len,
                                                  const char **ao_val,
                                                  uint32_t &ao_val_len,
                                                  void *a_ctx,
                                                  uint32_t a_idx)
{
        if(a_idx == 0)
        {
                *ao_key = "User-Agent";
                ao_key_len = strlen("User-Agent");
                *ao_val = "monkey";
                ao_val_len = strlen("monkey");
        }
        else
        {
                *ao_key = "Cookie";
                ao_key_len = strlen("Cookie");
                *ao_val = g_ec_cookie_val.c_str();
                ao_val_len = g_ec_cookie_val.length();
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_header_w_idx_bc_cb - both ua and cookie
//! ----------------------------------------------------------------------------
int32_t strip_token(std::string &ao_token, const char *a_resp, uint32_t a_resp_len)
{
        char *l_pos = NULL;
        l_pos = ns_waflz::strnstr(a_resp, "ec_secure=", a_resp_len);
        l_pos += sizeof("ec_secure=") - 1;
        char *l_end = l_pos;
        while(*l_end != '"') ++l_end;
        ao_token.assign(l_pos, (int)(l_end - l_pos));
        return 0;
}
//! ----------------------------------------------------------------------------
//! config tests
//! ----------------------------------------------------------------------------
TEST_CASE( "config browser challenge tests", "[config(bc)]" ) {
        ns_waflz::geoip2_mmdb l_geoip2_mmdb;
        // -------------------------------------------------
        // verify browser challenge for 'always_on' mode
        // -------------------------------------------------
        SECTION("verify browser challenge for always_on mode") {
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
                ns_waflz::challenge l_challenge;
                l_s = l_challenge.load(VALID_CHALLENGE_JSON, sizeof(VALID_CHALLENGE_JSON));
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                ns_waflz::config *l_c = new ns_waflz::config(l_db, l_challenge);
                l_s = l_c->load(CONFIG_W_ALWAYS_ON_MODE_BROWSER_CHALLENGE_JSON, sizeof(CONFIG_W_ALWAYS_ON_MODE_BROWSER_CHALLENGE_JSON));
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // load config - check limit is removed
                // from config
                // -----------------------------------------
                REQUIRE(l_c->get_pb()->limits_size() == 0);
                // -----------------------------------------
                // waflz obj
                // -----------------------------------------
                void *l_rctx = NULL;
                ns_waflz::rqst_ctx *l_ctx = NULL;
                const ::waflz_pb::enforcement *l_enf = NULL;
                const ::waflz_pb::limit* l_limit = NULL;
                // -----------------------------------------
                // set rqst_ctx
                // -----------------------------------------
                ns_waflz::rqst_ctx::s_get_rqst_src_addr_cb = get_rqst_ip_cb;
                ns_waflz::rqst_ctx::s_get_rqst_host_cb = get_rqst_host_cats_cb;
                ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_cats_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_bc_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_bc_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // process - first request. should
                // get browser challenge as enforcement
                // -----------------------------------------
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE(l_enf != NULL);
                REQUIRE(l_enf->has_enf_type());
                REQUIRE(l_enf->enf_type() == waflz_pb::enforcement_type_t_BROWSER_CHALLENGE);
                // -----------------------------------------
                // render resp
                // -----------------------------------------
                char *l_resp = NULL;
                uint32_t l_resp_len = 0;
                l_s = l_c->get_challenge().render_challenge(&l_resp, l_resp_len, l_ctx);
                REQUIRE((l_resp != NULL));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // strip ec token from html body, form
                // ec_secure cookie with wrong answer and
                // make a request again.
                // -----------------------------------------
                std::string l_token;
                strip_token(l_token, l_resp, l_resp_len);
                if(l_resp) { free(l_resp); l_resp = NULL; l_resp_len = 0; }
                // -----------------------------------------
                // create cookie
                // -----------------------------------------
                g_ec_cookie_val.clear();
                g_ec_cookie_val += "ec_secure=";
                g_ec_cookie_val += l_token.c_str();
                g_ec_cookie_val += "; ";
                g_ec_cookie_val += "ec_answer=";
                g_ec_cookie_val += "200";
                // -----------------------------------------
                // set new header callbacks
                // for getting cookie
                // -----------------------------------------
                ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_2_bc_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_bc_cookie_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // w/ wrong cookie, verify gets an another
                // browser challenge as enforcement
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_limit == NULL);
                REQUIRE(l_enf != NULL);
                REQUIRE(l_enf->has_enf_type());
                REQUIRE(l_enf->enf_type() == waflz_pb::enforcement_type_t_BROWSER_CHALLENGE);
                // -----------------------------------------
                // set correct cookie. verify no event
                // until cookie expiry
                // -----------------------------------------
                g_ec_cookie_val.clear();
                g_ec_cookie_val += "ec_secure=";
                g_ec_cookie_val += l_token.c_str();
                g_ec_cookie_val += "; ";
                g_ec_cookie_val += "ec_answer=";
                g_ec_cookie_val += "232";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // verify no match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int i=0; i < 5; ++i)
                {
                        l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // cookie expiration is set to 1 seconds
                // sleeping for 2 seconds should produce
                // new browser challenge enforcement
                // -----------------------------------------
                sleep(2);
                // -----------------------------------------
                // cookie should have expired and there
                // should be an enforcement for browser
                // challenge
                // -----------------------------------------
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE(l_enf != NULL);
                REQUIRE(l_enf->has_enf_type());
                REQUIRE(l_enf->enf_type() == waflz_pb::enforcement_type_t_BROWSER_CHALLENGE);
                // -----------------------------------------
                // render resp
                // -----------------------------------------
                l_s = l_c->get_challenge().render_challenge(&l_resp, l_resp_len, l_ctx);
                REQUIRE((l_resp != NULL));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // strip ec token from html body, form
                // ec_secure cookie with wrong answer and
                // make a request again.
                // -----------------------------------------
                strip_token(l_token, l_resp, l_resp_len);
                if(l_resp) { free(l_resp); l_resp = NULL; l_resp_len = 0; }
                // -----------------------------------------
                // set correct cookie.
                // -----------------------------------------
                g_ec_cookie_val.clear();
                g_ec_cookie_val += "ec_secure=";
                g_ec_cookie_val += l_token.c_str();
                g_ec_cookie_val += "; ";
                g_ec_cookie_val += "ec_answer=";
                g_ec_cookie_val += "232";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // set correct cookie.
                // verify no event until cookie expiry
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf == NULL));
                REQUIRE((l_limit == NULL));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                if(l_c) {delete l_c; l_c = NULL;}
                unlink(l_db_file);
        }
        // -------------------------------------------------
        // verify browser challenge as enforcement
        // -------------------------------------------------
        SECTION("verify browser challenge as enforcement") {
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
                ns_waflz::challenge l_challenge;
                l_s = l_challenge.load(VALID_CHALLENGE_JSON, sizeof(VALID_CHALLENGE_JSON));
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                ns_waflz::config *l_c = new ns_waflz::config(l_db, l_challenge);
                // -----------------------------------------
                // load config
                // -----------------------------------------
                l_s = l_c->load(CONFIG_W_BROWSER_CHALLENGE_ENFORCEMENT_JSON, sizeof(CONFIG_W_BROWSER_CHALLENGE_ENFORCEMENT_JSON));
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // waflz obj
                // -----------------------------------------
                void *l_rctx = NULL;
                ns_waflz::rqst_ctx *l_ctx = NULL;
                const ::waflz_pb::enforcement *l_enf = NULL;
                const ::waflz_pb::limit* l_limit = NULL;
                // -----------------------------------------
                // set rqst_ctx
                // -----------------------------------------
                ns_waflz::rqst_ctx::s_get_rqst_src_addr_cb = get_rqst_ip_cb;
                ns_waflz::rqst_ctx::s_get_rqst_host_cb = get_rqst_host_cats_cb;
                ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_cats_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_bc_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_bc_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // verify no enforcer
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int i=0; i<5; ++i)
                {
                        l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // enforcement should be present for the
                // sixth request
                // -----------------------------------------
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE((l_limit != NULL));
                REQUIRE(l_enf != NULL);
                REQUIRE(l_enf->has_enf_type());
                REQUIRE(l_enf->enf_type() == waflz_pb::enforcement_type_t_BROWSER_CHALLENGE);
                // -----------------------------------------
                // render resp
                // -----------------------------------------
                char *l_resp = NULL;
                uint32_t l_resp_len = 0;
                l_s = l_c->get_challenge().render_challenge(&l_resp, l_resp_len, l_ctx);
                REQUIRE((l_resp != NULL));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // strip ec token from html body, form
                // ec_secure cookie with wrong answer and
                // make a request again.
                // -----------------------------------------
                std::string l_token;
                strip_token(l_token, l_resp, l_resp_len);
                if(l_resp) { free(l_resp); l_resp = NULL; l_resp_len = 0; }
                // -----------------------------------------
                // set new header callbacks
                // for getting cookie
                // -----------------------------------------
                ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_2_bc_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_bc_cookie_cb;
                // -----------------------------------------
                // create cookie
                // -----------------------------------------
                g_ec_cookie_val.clear();
                g_ec_cookie_val += "ec_secure=";
                g_ec_cookie_val += l_token.c_str();
                g_ec_cookie_val += "; ";
                g_ec_cookie_val += "ec_answer=";
                g_ec_cookie_val += "200";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // validate get challenge for bad resp
                // -----------------------------------------
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE((l_limit == NULL));
                REQUIRE(l_enf != NULL);
                REQUIRE(l_enf->has_enf_type());
                REQUIRE(l_enf->enf_type() == waflz_pb::enforcement_type_t_BROWSER_CHALLENGE);
                // -----------------------------------------
                // create cookie
                // -----------------------------------------
                g_ec_cookie_val.clear();
                g_ec_cookie_val += "ec_secure=";
                g_ec_cookie_val += l_token.c_str();
                g_ec_cookie_val += "; ";
                g_ec_cookie_val += "ec_answer=";
                g_ec_cookie_val += "232";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //------------------------------------------
                // set correct cookie. verify no enforcer
                //------------------------------------------
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE((l_limit == NULL));
                REQUIRE(l_enf == NULL);
                //------------------------------------------
                // sleep for 4 seconds.both enforcer and 
                // cookie should have been expired
                // config should
                // start counting again
                //------------------------------------------
                sleep(4);
                // -----------------------------------------
                // verify no enforcer
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int i=0; i<5; ++i)
                {
                        l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // enforcement should be present for the
                // sixth request
                // -----------------------------------------
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE((l_limit != NULL));
                REQUIRE(l_enf != NULL);
                REQUIRE(l_enf->has_enf_type());
                REQUIRE(l_enf->enf_type() == waflz_pb::enforcement_type_t_BROWSER_CHALLENGE);
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                if(l_c) { delete l_c; l_c = NULL; }
                unlink(l_db_file);
        }
}

