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
#include <unistd.h>
#if 0
#include "waflz/engine.h"
#include "waflz/def.h"
#include "waflz/scopes.h"
#include "waflz/rqst_ctx.h"
#include "support/ndebug.h"
#include "jspb/jspb.h"
#include "event.pb.h"
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#endif
//! ----------------------------------------------------------------------------
//! Config
//! ----------------------------------------------------------------------------
// TODO
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
#if 0
static int32_t get_rqst_src_addr_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_uri[] = "243.49.2.0";
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_line_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "GET /800050/origin.testsuite.com/sec_arg_check/info.html?a=%27select%20*%20from%20test_5%27 HTTP/1.1";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_method_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "GET";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_protocol_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "HTTP/1.1";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_scheme_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "http";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_port_cb(uint32_t &a_val, void *a_ctx)
{
        a_val = 80;
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_uri_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "/800050/origin.testsuite.com/sec_arg_check/info.html?a=%27select%20*%20from%20test_5%27";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_query_str_long_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "mooooooooooooooooooooooooooooooooooooooooooooooooooooonnnnnnnnnnnnnnnnkkkkkkkkkkkkkkkkkkeeeeeeeeeeeeeeeyyyyyyyyyyssssss=100000000000000000000000000000000000000";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_query_str_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "a=%27select%20*%20from%20test_5%27";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t &a_val, void *a_ctx)
{
        a_val = 3;
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_w_idx_cb(const char **ao_key,
                                        uint32_t &ao_key_len,
                                        const char **ao_val,
                                        uint32_t &ao_val_len,
                                        void *a_ctx,
                                        uint32_t a_idx)
{
        switch(a_idx)
        {
        case 0:
        {
                static const char s_host_key[] = "Host";
                *ao_key = s_host_key;
                ao_key_len = strlen(s_host_key);
                static const char s_host_val[] = "www.google.com";
                *ao_val = s_host_val;
                ao_val_len = strlen(s_host_val);
                break;
        }
        case 1:
        {
                static const char s_ua_key[] = "User-Agent";
                *ao_key = s_ua_key;
                ao_key_len = strlen(s_ua_key);
                static const char s_ua_val[] = "curl/7.47.0";
                *ao_val = s_ua_val;
                ao_val_len = strlen(s_ua_val);
                break;
        }
        case 2:
        {
                static const char s_acct_key[] = "Accept";
                *ao_key = s_acct_key;
                ao_key_len = strlen(s_acct_key);
                static const char s_acct_val[] = "*/*";
                *ao_val = s_acct_val;
                ao_val_len = strlen(s_acct_val);
                break;
        }
        default:
        {
                static const char s_host_key_d[] = "Host";
                *ao_key = s_host_key_d;
                ao_key_len = strlen(s_host_key_d);
                static const char s_host_value_d[] = "www.google.com";
                *ao_val = s_host_value_d;
                ao_val_len = strlen(s_host_value_d);
                break;
        }
        }
        return 0;
}
#endif
//! ----------------------------------------------------------------------------
//! instances tests
//! ----------------------------------------------------------------------------
TEST_CASE( "scopes test", "[scopes]" ) {

        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        SECTION("verify load") {
                // -----------------------------------------
                // get ruleset dir
                // -----------------------------------------
                char l_cwd[1024];
                if (getcwd(l_cwd, sizeof(l_cwd)) != NULL)
                {
                    //fprintf(stdout, "Current working dir: %s\n", l_cwd);
                }
                std::string l_rule_dir = l_cwd;
                l_rule_dir += "/../../../../tests/data/waf/ruleset/";
                //l_rule_dir += "/../tests/data/waf/ruleset/";
                //set_trace(true);
                // -----------------------------------------
                // geo ip dbs
                // -----------------------------------------
                std::string l_geoip2_city_file = l_cwd;
                std::string l_geoip2_asn_file = l_cwd;
                l_geoip2_city_file += "/../../../../tests/data/waf/db/GeoLite2-City.mmdb";
                l_geoip2_asn_file += "/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb";
#if 0
                // -----------------------------------------
                // callbacks
                // -----------------------------------------
                ns_waflz::rqst_ctx::s_get_rqst_src_addr_cb = get_rqst_src_addr_cb;
                ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_cb;
                ns_waflz::rqst_ctx::s_get_rqst_query_str_cb = get_rqst_query_str_cb;
                ns_waflz::rqst_ctx::s_get_rqst_line_cb = get_rqst_line_cb;
                ns_waflz::rqst_ctx::s_get_rqst_scheme_cb = get_rqst_scheme_cb;
                ns_waflz::rqst_ctx::s_get_rqst_port_cb = get_rqst_port_cb;
                ns_waflz::rqst_ctx::s_get_rqst_method_cb = get_rqst_method_cb;
                ns_waflz::rqst_ctx::s_get_rqst_protocol_cb = get_rqst_protocol_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_cb;
                //ns_waflz::rqst_ctx::s_get_rqst_id_cb = get_rqst_id_cb;
                // -----------------------------------------
                // init
                // -----------------------------------------
                ns_waflz::engine *l_engine = new ns_waflz::engine();
                l_engine->set_ruleset_dir(l_rule_dir);
                l_engine->set_geoip2_dbs(l_geoip2_city_file, l_geoip2_asn_file);
                int32_t l_s;
                l_s = l_engine->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::instances *l_ix;
                ns_waflz::instance *l_i = NULL;
                l_ix = new ns_waflz::instances(*l_engine);
                REQUIRE((l_ix != NULL));
                NDBG_OUTPUT("%s\n", WAF_CONF_1001_JSON);
                l_s = l_ix->load(&l_i, WAF_CONF_1001_JSON, sizeof(WAF_CONF_1001_JSON), true);
                NDBG_PRINT("err_msg: %s\n", l_ix->get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
#if 0
                REQUIRE((l_i != NULL));
                REQUIRE((l_i->get_id() == "1001"));
                // -----------------------------------------
                // get instance
                // -----------------------------------------
                l_i = NULL;
                l_i = l_ix->get_instance("1001");
                REQUIRE((l_i != NULL));
                REQUIRE((l_i->get_id() == "1001"));
                // -----------------------------------------
                // verify update fail
                // -----------------------------------------
                l_s = l_ix->load(&l_i, WAF_CONF_1002_JSON, sizeof(WAF_CONF_1002_JSON), true, true);
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
                // -----------------------------------------
                // verify update success
                // -----------------------------------------
                l_s = l_ix->load(&l_i, WAF_CONF_1001_JSON, sizeof(WAF_CONF_1001_JSON), true, true);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // process
                // -----------------------------------------
                waflz_pb::event *l_event = NULL;
                std::string l_id("1001");
                l_i = l_ix->get_instance(l_id);
                l_ix->set_locking(true);
                REQUIRE((l_i != NULL));
                REQUIRE((l_i->get_id() == "1001"));
                ns_waflz::rqst_ctx::s_get_rqst_query_str_cb = get_rqst_query_str_long_cb;
                for(int i = 0; i < 2; ++i)
                {
                        int32_t l_s;
                        void *l_ctx = NULL;
                        if(i == 0)
                        {
                                l_s = l_ix->process_audit(&l_event, l_ctx, l_id);
                                if(l_event)
                                {
                                        delete l_event;
                                        l_event = NULL;
                                }
                        }
                        else if(i == 1)
                        {
                                l_s = l_ix->process_prod(&l_event, l_ctx, l_id);
                                if(l_event)
                                {
                                        delete l_event;
                                        l_event = NULL;
                                }
                        }

                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                }
                // -----------------------------------------
                // load configs tests with
                // last_modified_date
                // -----------------------------------------
                // -----------------------------------------
                // load with last_modified_date
                // -----------------------------------------
                l_s = l_ix->load(&l_i, WAF_CONF_1001_W_LM_DATE_JSON, sizeof(WAF_CONF_1001_W_LM_DATE_JSON), true, false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_i != NULL));
                REQUIRE((l_i->get_id() == "1001"));
                REQUIRE((l_i->get_pb()->last_modified_date() == "2016-07-20T00:45:20.744583Z"));
                // -----------------------------------------
                // load with new last_modified_date
                // -----------------------------------------
                l_s = l_ix->load(&l_i, WAF_CONF_1001_W_NEW_LM_DATE_JSON, sizeof(WAF_CONF_1001_W_NEW_LM_DATE_JSON), true, true);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_i != NULL));
                REQUIRE((l_i->get_id() == "1001"));
                REQUIRE((l_i->get_pb()->last_modified_date() == "2016-08-25T00:45:20.744583Z"));
                // -----------------------------------------
                // load with old last_modified_date
                // -----------------------------------------
                l_s = l_ix->load(&l_i, WAF_CONF_1001_W_LM_DATE_JSON, sizeof(WAF_CONF_1001_W_LM_DATE_JSON), true, true);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_i != NULL));
                REQUIRE((l_i->get_id() == "1001"));
                REQUIRE((l_i->get_pb()->last_modified_date() == "2016-08-25T00:45:20.744583Z"));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                l_engine->shutdown();
                if(l_event)
                {
                        delete l_event;
                        l_event = NULL;
                }
#endif
                if(l_ix)
                {
                        delete l_ix;
                        l_ix = NULL;
                }
                if(l_engine)
                {
                        delete l_engine;
                        l_engine = NULL;
                }
#endif
        }
}
