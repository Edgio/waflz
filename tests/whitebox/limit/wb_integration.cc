//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_integration.cc
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
//: includes
//: ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "jspb/jspb.h"
#include "support/time_util.h"
#include "waflz/def.h"
#include "waflz/enforcer.h"
#include "waflz/config.h"
#include "waflz/kycb_db.h"
#include "waflz/rqst_ctx.h"
#include "waflz/geoip2_mmdb.h"
#include "limit.pb.h"
#include <string.h>
#include <unistd.h>
//: ----------------------------------------------------------------------------
//: Config
//: ----------------------------------------------------------------------------
#define COORDINATOR_CONFIG_JSON_NO_RULES \
"{"\
"  \"version\": 2,"\
"  \"id\": \"b9882f74-fdc0-4bcc-89ae-36c808e9497916715\","\
"  \"name\": \"name\","\
"  \"type\": \"CONFIG\","\
"  \"customer_id\": \"16715\","\
"  \"enabled_date\": \"2016-07-20T00:44:20.744583Z\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"080c5799-78b1-470f-91af-f1c999be94cb16715\","\
"      \"name\": \"RULE_STUFF\","\
"      \"disabled\": false,"\
"      \"duration_sec\": 1,"\
"      \"num\": 7,"\
"      \"keys\": ["\
"        \"IP\","\
"        \"USER_AGENT\""\
"      ],"\
"      \"action\": {"\
"        \"id\": \"28b3de98-b3e1-4642-ac77-50d2fe69fab416715\","\
"        \"name\": \"STUFF\","\
"        \"type\": \"redirect-302\","\
"        \"url\": \"https://www.google.com\","\
"        \"enf_type\": \"REDIRECT_302\""\
"      }"\
"    }"\
"  ]"\
"}"\

//: ----------------------------------------------------------------------------
//: get_rqst_header_size_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t &a_val, void *a_ctx)
{
        a_val = 1;
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_header_w_idx_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_header_w_idx_1_cb(const char **ao_key,
                                          uint32_t &ao_key_len,
                                          const char **ao_val,
                                          uint32_t &ao_val_len,
                                          void *a_ctx,
                                          uint32_t a_idx)
{
        if(a_idx == 0)
        {
                *ao_key = "User-Agent";
                ao_key_len = sizeof("User-Agent");
                *ao_val = "monkey";
                ao_val_len = sizeof("monkey");
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_header_w_idx_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_header_w_idx_2_cb(const char **ao_key,
                                          uint32_t &ao_key_len,
                                          const char **ao_val,
                                          uint32_t &ao_val_len,
                                          void *a_ctx,
                                          uint32_t a_idx)
{
        if(a_idx == 0)
        {
                *ao_key = "User-Agent";
                ao_key_len = sizeof("User-Agent");
                *ao_val = "banana";
                ao_val_len = sizeof("banana");
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: get ip callback
//: ----------------------------------------------------------------------------
static int32_t get_rqst_src_addr_cb(const char **a_data,
                                    uint32_t &a_len,
                                    void *a_ctx)
{
        static const char s_ip[] = "233.87.123.171";
        *a_data = s_ip;
        a_len = strlen(s_ip);
        return 0;
}
//: ----------------------------------------------------------------------------
//: config tests
//: ----------------------------------------------------------------------------
TEST_CASE( "no rules test", "[no_rules]" ) {
        ns_waflz::geoip2_mmdb l_geoip2_mmdb;
        // -------------------------------------------------
        // Valid config
        // -------------------------------------------------
        SECTION("verify config behavior with dimensions only") {
                // -----------------------------------------
                // db setup
                // -----------------------------------------
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
                // -----------------------------------------
                // setup config
                // -----------------------------------------
                ns_waflz::config l_c(l_db, l_challenge);
                l_s = l_c.load(COORDINATOR_CONFIG_JSON_NO_RULES, sizeof(COORDINATOR_CONFIG_JSON_NO_RULES));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
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
                ns_waflz::rqst_ctx::s_get_rqst_src_addr_cb = get_rqst_src_addr_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_1_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // run requests
                // -----------------------------------------
                // Verify no match
                for(int i=0; i<7; ++i)
                {
                        l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // verify enforcer
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "28b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_enf->has_type()));
                REQUIRE((l_enf->type() == "redirect-302"));
                REQUIRE((l_limit != NULL));
                REQUIRE((l_limit->has_id()));
                REQUIRE((l_limit->id() == "080c5799-78b1-470f-91af-f1c999be94cb16715"));
                // -----------------------------------------
                // switch user agent
                // verify no enforcement
                // -----------------------------------------
                ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_2_cb;
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
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf == NULL));
                // -----------------------------------------
                // switch user agent back
                // verify enforcement
                // -----------------------------------------
                ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_1_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // verify match
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "28b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_enf->has_type()));
                REQUIRE((l_enf->type() == "redirect-302"));
                REQUIRE((l_limit == NULL));
                // -----------------------------------------
                // wait for expire
                // -----------------------------------------
                sleep(2);
                // -----------------------------------------
                // verify no enforcement
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf == NULL));
                REQUIRE((l_limit == NULL));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                unlink(l_db_file);
        }
}

