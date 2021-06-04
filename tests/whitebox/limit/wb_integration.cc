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
#include "jspb/jspb.h"
#include "support/time_util.h"
#include "waflz/def.h"
#include "waflz/enforcer.h"
#include "waflz/config.h"
#include "waflz/rqst_ctx.h"
#include "waflz/geoip2_mmdb.h"
#include "limit.pb.h"
#include <string.h>
#include <unistd.h>
//! ----------------------------------------------------------------------------
//! Config
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
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

//! ----------------------------------------------------------------------------
//! get_rqst_header_size_cb
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t *a_val, void *a_ctx)
{
        *a_val = 1;
        return 0;
}
static const char *s_header_user_agent = "monkey";

static int32_t get_rqst_header_w_idx_cb(const char **ao_key,
                                        uint32_t *ao_key_len,
                                        const char **ao_val,
                                        uint32_t *ao_val_len,
                                        void *a_ctx,
                                        uint32_t a_idx)
{
        *ao_key = NULL;
        *ao_key_len = 0;
        *ao_val = NULL;
        *ao_val_len = 0;
        switch(a_idx)
        {
        case 0:
        {
                *ao_key = "User-Agent";
                *ao_key_len = strlen("User-Agent");
                *ao_val = s_header_user_agent;
                *ao_val_len = strlen(s_header_user_agent);
                break;
        }
        default:
        {
                break;
        }
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! get ip callback
//! ----------------------------------------------------------------------------
static const char *s_ip = "233.87.123.171";
static int32_t get_rqst_src_addr_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        *a_data = s_ip;
        *a_len = strlen(s_ip);
        return 0;
}
//! ----------------------------------------------------------------------------
//! config tests
//! ----------------------------------------------------------------------------
TEST_CASE( "no rules test", "[no_rules]" ) {
        static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                        get_rqst_src_addr_cb,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        get_rqst_header_size_cb,
                        NULL, //get_rqst_header_w_key_cb,
                        get_rqst_header_w_idx_cb,
                        NULL,
                        NULL, //get_rqst_local_addr_cb,
                        NULL, //get_rqst_canonical_port_cb,
                        NULL, //get_rqst_apparent_cache_status_cb,
                        NULL, //get_rqst_bytes_out_cb,
                        NULL, //get_rqst_bytes_in_cb,
                        NULL, //get_rqst_uuid_cb,
                        NULL //get_cust_id_cb
        };
        ns_waflz::geoip2_mmdb l_geoip2_mmdb;
        // -------------------------------------------------
        // Valid config
        // -------------------------------------------------
        SECTION("verify config behavior with dimensions only") {
                // -----------------------------------------
                // TODO FIX!!!
                // -----------------------------------------
#if 0
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
                // -----------------------------------------
                // setup config
                // -----------------------------------------
                ns_waflz::config l_c(l_db);
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
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
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
                s_header_user_agent = "banana";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
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
                s_header_user_agent = "monkey";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
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
#endif
        }
}

