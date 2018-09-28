//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_profile_acl.cc
//: \details: TODO
//: \author:  Reed Morrison
//: \date:    12/30/2017
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
#include "waflz/engine.h"
#include "waflz/profile.h"
#include "waflz/instances.h"
#include "waflz/rqst_ctx.h"
#include "waflz/def.h"
#include "config.pb.h"
#include "event.pb.h"
#include "support/ndebug.h"
#include "support/geoip2_mmdb.h"
#include <unistd.h>
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static waflz_pb::profile *init_std_profile_pb(void)
{
        // -----------------------------------------
        // setup...
        // -----------------------------------------
        waflz_pb::profile *l_pb = NULL;
        l_pb = new waflz_pb::profile();
        l_pb->set_id("my_id");
        l_pb->set_name("my_name");
        l_pb->set_ruleset_id("OWASP-CRS-2.2.9");
        l_pb->set_ruleset_version("2017-08-01");
        // -----------------------------------------
        // general settings -required fields
        // -----------------------------------------
        ::waflz_pb::profile_general_settings_t* l_gx = NULL;
        l_gx = l_pb->mutable_general_settings();
        l_gx->set_process_request_body(true);
        l_gx->set_xml_parser(true);
        l_gx->set_process_response_body(false);
        l_gx->set_engine("anomaly");
        l_gx->set_validate_utf8_encoding(true);
        l_gx->set_max_num_args(3);
        l_gx->set_arg_name_length(100);
        l_gx->set_arg_length(400);
        l_gx->set_total_arg_length(64000);
        l_gx->set_max_file_size(1048576);
        l_gx->set_combined_file_sizes(1048576);
        l_gx->add_allowed_http_methods("GET");
        l_gx->add_allowed_request_content_types("html");
        // -----------------------------------------
        // anomaly settings -required fields
        // -----------------------------------------
        ::waflz_pb::profile_general_settings_t_anomaly_settings_t* l_gx_anomaly = NULL;
        l_gx_anomaly = l_gx->mutable_anomaly_settings();
        l_gx_anomaly->set_critical_score(5);
        l_gx_anomaly->set_error_score(4);
        l_gx_anomaly->set_warning_score(3);
        l_gx_anomaly->set_notice_score(2);
        l_gx_anomaly->set_inbound_threshold(1);
        l_gx_anomaly->set_outbound_threshold(4);
        // -----------------------------------------
        // access settings -required fields
        // -----------------------------------------
        ::waflz_pb::profile_access_settings_t* l_ax = NULL;
        l_ax = l_pb->mutable_access_settings();
        ::waflz_pb::profile_access_settings_t_lists_t* l_ax_ip = l_ax->mutable_ip();
        UNUSED(l_ax_ip);
        ::waflz_pb::profile_access_settings_t_lists_t* l_ax_cntry = l_ax->mutable_country();
        UNUSED(l_ax_cntry);
        ::waflz_pb::profile_access_settings_t_lists_t* l_ax_url = l_ax->mutable_url();
        UNUSED(l_ax_url);
        ::waflz_pb::profile_access_settings_t_lists_t* l_ax_refr = l_ax->mutable_referer();
        UNUSED(l_ax_refr);
        return l_pb;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static const char *s_ip = "156.123.12.7";
static int32_t get_rqst_src_addr_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        *a_data = s_ip;
        a_len = strlen(s_ip);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_line_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "GET / HTTP/1.1";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static const char *s_uri = "cats.com";
static int32_t get_rqst_uri_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_header_size_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t &a_val, void *a_ctx)
{
        a_val = 8;
        return 0;
}
//: ----------------------------------------------------------------------------
//: s_get_rqst_method_cb
//: ----------------------------------------------------------------------------
static const char *s_method = "GET";
static int32_t get_rqst_method_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        *a_data = s_method;
        a_len = strlen(s_method);
        return 0;
}
//: ----------------------------------------------------------------------------
//: s_get_rqst_path_cb
//: ----------------------------------------------------------------------------
static const char *s_path = "/my/cool/path_name.html";
static int32_t get_rqst_path_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        *a_data = s_path;
        a_len = strlen(s_path);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_header_w_idx_cb
//: ----------------------------------------------------------------------------
#if 0
> User-Agent: curl/7.47.0
> Accept: *
> Referer: google.com
> Cookie:__cfduid=de8f54f306ad55fdcbd9a4b2d74e146011505283099; _ga=GA1.2.1776379976.1505283191; __utmz=214959637.1507590369.3.3.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided); _gid=GA1.2.2014252890.1514820827; _gat_gtag_UA_33089744_1=1; __utma=214959637.1776379976.1505283191.1507590369.1514820827.4; __utmc=214959637; __utmt=1; __utmb=214959637.1.10.1514820827
#endif
static const char *s_header_user_agent = "my_cool_user_agent";
static const char *s_header_accept = "my_cool_accept_value";
static const char *s_header_referer = "my_cool_referer_value";
static const char *s_header_cookie = "__cookie_a=a_value; __cookie_b=b_value; __cookie_c=c_value;";
static const char *s_header_content_type = NULL;
static const char *s_header_content_length = NULL;
static const char *s_host = NULL;
static const char *s_test_header = NULL;
static int32_t get_rqst_header_w_idx_cb(const char **ao_key,
                                        uint32_t &ao_key_len,
                                        const char **ao_val,
                                        uint32_t &ao_val_len,
                                        void *a_ctx,
                                        uint32_t a_idx)
{
        *ao_key = NULL;
        ao_key_len = 0;
        *ao_val = NULL;
        ao_val_len = 0;
        switch(a_idx)
        {
        case 0:
        {
                *ao_key = "User-Agent";
                ao_key_len = strlen("User-Agent");
                *ao_val = s_header_user_agent;
                ao_val_len = strlen(s_header_user_agent);
                break;
        }
        case 1:
        {
                *ao_key = "Accept";
                ao_key_len = strlen("Accept");
                *ao_val = s_header_accept;
                ao_val_len = strlen(s_header_accept);
                break;
        }
        case 2:
        {
                *ao_key = "Referer";
                ao_key_len = strlen("Referer");
                *ao_val = s_header_referer;
                ao_val_len = strlen(s_header_referer);
                break;
        }
        case 3:
        {
                *ao_key = "Cookie";
                ao_key_len = strlen("Cookie");
                *ao_val = s_header_cookie;
                ao_val_len = strlen(s_header_cookie);
                break;
        }
        case 4:
        {
                if(s_header_content_type)
                {
                        *ao_key = "Content-Type";
                        ao_key_len = strlen("Content-Type");
                        *ao_val = s_header_content_type;
                        ao_val_len = strlen(s_header_content_type);
                }
                break;
        }
        case 5:
        {
                if(s_header_content_length)
                {
                        *ao_key = "Content-Length";
                        ao_key_len = strlen("Content-Length");
                        *ao_val = s_header_content_length;
                        ao_val_len = strlen(s_header_content_length);
                }
                break;
        }
        case 6:
        {
                if(s_host)
                {
                        *ao_key = "Host";
                        ao_key_len = strlen("Host");
                        *ao_val = s_host;
                        ao_val_len = strlen(s_host);
                }
                break;
        }
        case 7:
        {
                if(s_test_header)
                {
                        *ao_key = s_test_header;
                        ao_key_len = strlen(s_test_header);
                        *ao_val = s_test_header;
                        ao_val_len = strlen(s_test_header);
                }
                break;
        }
        default:
        {
                break;
        }
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: profile acl tests
//: ----------------------------------------------------------------------------
TEST_CASE( "profile acls test", "[profile_acls]" )
{
        // -----------------------------------------
        // get ruleset dir
        // -----------------------------------------
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
            //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        std::string l_rule_dir = l_cwd;
        l_rule_dir += "/../../../../tests/data/waf/ruleset/";
        //l_rule_dir += "/../tests/data/waf/ruleset/";
        ns_waflz::profile::s_ruleset_dir = l_rule_dir;
        // -----------------------------------------
        // geoip
        // -----------------------------------------
        std::string l_geoip2_city_file = l_cwd;
        std::string l_geoip2_asn_file = l_cwd;
        l_geoip2_city_file += "/../../../../tests/data/waf/db/GeoLite2-City.mmdb";
        //l_geoip2_city_file += "/../tests/data/waf/db/GeoLite2-City.mmdb";
        l_geoip2_asn_file += "/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb";
        //l_geoip2_asn_file += "/../tests/data/waf/db/GeoLite2-ASN.mmdb";
        ns_waflz::profile::s_geoip2_db = l_geoip2_city_file;
        ns_waflz::profile::s_geoip2_isp_db = l_geoip2_asn_file;
        // -------------------------------------------------
        // acl
        // -------------------------------------------------
        SECTION("acl tests") {
                // -----------------------------------------
                // setup
                // -----------------------------------------
                ns_waflz::geoip2_mmdb *l_geoip2_mmdb = new ns_waflz::geoip2_mmdb();
                int32_t l_s;
                l_s = l_geoip2_mmdb->init(ns_waflz::profile::s_geoip2_db,
                                          ns_waflz::profile::s_geoip2_isp_db);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::engine *l_engine = new ns_waflz::engine();
                l_s = l_engine->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_engine->init_post_fork();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine, *l_geoip2_mmdb);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                // *****************************************
                // -----------------------------------------
                // ip settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::profile_access_settings_t_lists_t* l_ax_ipl = l_pb->mutable_access_settings()->mutable_ip();
                l_ax_ipl->add_blacklist("212.43.2.0/16");
                l_ax_ipl->add_blacklist("243.49.2.7");
                l_ax_ipl->add_whitelist("200.162.133.3");
                l_ax_ipl->add_whitelist("199.167.1.0/8");
                l_ax_ipl->add_blacklist("199.167.1.1");
                // *****************************************
                // -----------------------------------------
                // country settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::profile_access_settings_t_lists_t* l_ax_ctyl = l_pb->mutable_access_settings()->mutable_country();
                l_ax_ctyl->add_blacklist("CN");
                l_ax_ctyl->add_whitelist("JP");
                // *****************************************
                // -----------------------------------------
                // asn settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::profile_access_settings_t_lists_asn_t* l_ax_asn = l_pb->mutable_access_settings()->mutable_asn();
                l_ax_asn->add_blacklist(26496);
                l_ax_asn->add_whitelist(15133);
                // *****************************************
                // -----------------------------------------
                // url settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::profile_access_settings_t_lists_t* l_ax_url = l_pb->mutable_access_settings()->mutable_url();
                l_ax_url->add_blacklist("/login-confirm/index.html");
                l_ax_url->add_blacklist("\\/banana\\/m.*\\.html");
                l_ax_url->add_whitelist("/chickenkiller/kill_chickenzz.html");
                // *****************************************
                // -----------------------------------------
                // user-agent settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::profile_access_settings_t_lists_t* l_ax_ua = l_pb->mutable_access_settings()->mutable_user_agent();
                l_ax_ua->add_blacklist("cats are really cool dude");
                l_ax_ua->add_blacklist("curl\\/.*");
                l_ax_ua->add_whitelist("monkeys luv bananas");
                // *****************************************
                // -----------------------------------------
                // referer settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::profile_access_settings_t_lists_t* l_ax_refr = l_pb->mutable_access_settings()->mutable_referer();
                l_ax_refr->add_blacklist("bad reefer");
                l_ax_refr->add_blacklist("really\\/bad\\/.*");
                l_ax_refr->add_whitelist("monkeys luv referers");
                // *****************************************
                // -----------------------------------------
                // cookie settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::profile_access_settings_t_lists_t* l_ax_cookie = l_pb->mutable_access_settings()->mutable_cookie();
                l_ax_cookie->add_blacklist("bad_[0-9]_key");
                l_ax_cookie->add_blacklist("wonky_key");
                l_ax_cookie->add_blacklist("wonky_value");
                l_ax_cookie->add_whitelist("monkeys_cookie");
                // *****************************************
                // -----------------------------------------
                // method settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::profile_general_settings_t *l_gx_settings = l_pb->mutable_general_settings();
                l_gx_settings->add_allowed_http_methods("GET");
                l_gx_settings->add_allowed_http_methods("POST");
                l_gx_settings->add_allowed_http_methods("OPTIONS");
                // *****************************************
                // -----------------------------------------
                // content type settings
                // -----------------------------------------
                // *****************************************
                //::waflz_pb::profile_general_settings_t* l_gx_content_type = l_pb->mutable_general_settings()->mutable_allowed_request_content_types();
                l_gx_settings->add_allowed_request_content_types("application/json");
                l_gx_settings->add_allowed_request_content_types("text/xml");
                // -----------------------------------------
                // disallowed_extensions settings
                // -----------------------------------------
                // *****************************************
                //::waflz_pb::profile_general_settings_t* l_gx_dis_ext = l_pb->mutable_general_settings()->mutable_disallowed_extensions();
                l_gx_settings->add_disallowed_extensions(".txt");
                l_gx_settings->add_disallowed_extensions(".php");
                // -----------------------------------------
                // disallowed_headers settings
                // -----------------------------------------
                // *****************************************
                //::waflz_pb::profile_general_settings_t* l_gx_dis_ext = l_pb->mutable_general_settings()->mutable_disallowed_extensions();
                l_gx_settings->add_disallowed_headers("test");
                // -----------------------------------------
                // load
                // -----------------------------------------
                l_s = l_profile->load_config(l_pb, false);
                //NDBG_PRINT("error[%d]: %s\n", l_s, l_profile->get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                if(l_pb) { delete l_pb; l_pb = NULL;}
                // -----------------------------------------
                // finalize
                // -----------------------------------------
                l_engine->finalize();
                // -----------------------------------------
                // cb
                // -----------------------------------------
                ns_waflz::rqst_ctx::s_get_rqst_src_addr_cb = get_rqst_src_addr_cb;
                ns_waflz::rqst_ctx::s_get_rqst_line_cb = get_rqst_line_cb;
                ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_cb;
                ns_waflz::rqst_ctx::s_get_rqst_method_cb = get_rqst_method_cb;
                ns_waflz::rqst_ctx::s_get_rqst_path_cb = get_rqst_path_cb;
                void *l_ctx = NULL;
                waflz_pb::event *l_event = NULL;
                s_ip = "200.163.1.17";
                // *****************************************
                // -----------------------------------------
                //             I P   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate std
                // -----------------------------------------
                s_ip = "200.163.1.17";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Request Missing a Host Header"));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist
                // -----------------------------------------
                s_ip = "243.49.2.7";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist IP match"));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist cidr
                // -----------------------------------------
                s_ip = "212.43.8.7";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist IP match"));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_ip = "200.162.133.3";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // validate whitelist cidr
                // -----------------------------------------
                s_ip = "199.167.1.17";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // validate whitelist included in blacklist
                // -----------------------------------------
                s_ip = "199.167.1.1";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_ip = "172.217.4.142";
                // *****************************************
                // -----------------------------------------
                //         C O U N T R Y   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate std
                // -----------------------------------------
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Request Missing a Host Header"));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist
                // -----------------------------------------
                s_ip = "45.249.212.124";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist Country match"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_ip = "202.32.115.5";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_ip = "172.217.4.142";
                // *****************************************
                // -----------------------------------------
                //             A S N   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate std
                // -----------------------------------------
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Request Missing a Host Header"));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist
                // -----------------------------------------
                s_ip = "160.153.43.133";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist ASN match"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_ip = "72.21.92.7";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_ip = "172.217.4.142";
                // *****************************************
                // -----------------------------------------
                //            U R L   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate std
                // -----------------------------------------
                s_uri = "/blabbleblabble/glubble.html";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Request Missing a Host Header"));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist
                // -----------------------------------------
                s_uri = "/login-confirm/index.html";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist URL match"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist regex
                // -----------------------------------------
                s_uri = "/banana/monkey.html";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist URL match"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_uri = "/chickenkiller/kill_chickenzz.html";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_uri = "/blabbleblabble/glubble.html";
                // *****************************************
                // -----------------------------------------
                //     U S E R - A G E N T   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate std
                // -----------------------------------------
                s_header_user_agent = "my_cool_user_agent";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Request Missing a Host Header"));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist
                // -----------------------------------------
                s_header_user_agent = "cats are really cool dude";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist User-Agent match"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist regex
                // -----------------------------------------
                s_header_user_agent = "curl/7.47.0";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist User-Agent match"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_header_user_agent = "monkeys luv bananas";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_header_user_agent = "my_cool_user_agent";
                // *****************************************
                // -----------------------------------------
                //        R E F E R E R   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate std
                // -----------------------------------------
                s_header_referer = "my_cool_referer_value";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Request Missing a Host Header"));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist
                // -----------------------------------------
                s_header_referer = "bad reefer";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist Referer match"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist regex
                // -----------------------------------------
                s_header_referer = "really/bad/reefer";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist Referer match"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_header_referer = "monkeys luv referers";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_header_referer = "my_cool_referer_value";
                // *****************************************
                // -----------------------------------------
                //        C O O K I E   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate std
                // -----------------------------------------
                s_header_cookie = "__cookie_a=a_value; __cookie_b=b_value; __cookie_c=c_value;";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Request Missing a Host Header"));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist key
                // -----------------------------------------
                s_header_cookie = "__cookie_a=a_value; wonky_key=b_value; __cookie_c=c_value;";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist Cookie match"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist value
                // -----------------------------------------
                s_header_cookie = "__cookie_a=a_value; __cookie_b=wonky_value; __cookie_c=c_value;";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist Cookie match"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist regex
                // -----------------------------------------
                s_header_cookie = "__cookie_a=a_value; bad_7_key=b_value; __cookie_c=c_value;";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist Cookie match"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_header_cookie = "__cookie_a=a_value; monkeys_cookie=b_value; __cookie_c=c_value;";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_header_cookie = "__cookie_a=a_value; __cookie_b=b_value; __cookie_c=c_value;";
                // *****************************************
                // -----------------------------------------
                //        M E T H O D  C H E C K
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate block
                // -----------------------------------------
                s_method = "HEAD";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).rule_id() == 80009));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Method is not allowed by policy"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate allow
                // -----------------------------------------
                s_method = "GET";
                s_host = "www.google.com";
                l_s = l_profile->process(&l_event, l_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_host = NULL;
                // *****************************************
                // -----------------------------------------
                //      C O N T E N T  T Y P E  C H E C K
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate block
                // -----------------------------------------
                s_header_content_type = "garbage type";
                s_header_content_length = "120";
                s_method = "POST";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).rule_id() == 80002));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Request content type is not allowed by policy"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate allow content for GET
                // -----------------------------------------
                s_method = "GET";
                s_host = "www.google.com";
                s_header_content_length = NULL;
                l_s = l_profile->process(&l_event, l_ctx);
                if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // validate allow content for OPTIONS
                // -----------------------------------------
                s_method = "OPTIONS";
                s_host = "www.google.com";
                s_header_content_length = NULL;
                l_s = l_profile->process(&l_event, l_ctx);
                if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_host = NULL;
                s_method = "GET";
                s_header_content_type = NULL;
                s_header_content_length = NULL;
                // *****************************************
                // -----------------------------------------
                //      F I L E  E X T  C H E C K
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate block
                // -----------------------------------------
                s_path = "my/path/is/abc.def.php";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).rule_id() == 80005));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "File extension is not allowed by policy"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate allow
                // -----------------------------------------
                s_host = "www.google.com";
                s_path = "my/path/is/abc.html";
                l_s = l_profile->process(&l_event, l_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_host = NULL;
                s_method = "GET";
                // *****************************************
                // -----------------------------------------
                //      F I L E  S I Z E  C H E C K
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate block
                // -----------------------------------------
                s_header_content_type = "text/xml";
                s_host = "www.google.com";
                s_method = "POST";
                s_header_content_length = "1048577";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).rule_id() == 80006));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Uploaded file size too large"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate allow
                // -----------------------------------------
                s_header_content_type = "text/xml";
                s_header_content_length = "120";
                s_host = "www.google.com";
                l_s = l_profile->process(&l_event, l_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_host = NULL;
                s_method = "GET";
                s_header_content_length = NULL;
                // *****************************************
                // -----------------------------------------
                //      HEADER  C H E C K
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate block
                // -----------------------------------------
                s_test_header = "test";
                s_host = "www.google.com";
                l_s = l_profile->process(&l_event, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).rule_id() == 80007));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Request header is not allowed by policy"));
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate allow
                // -----------------------------------------
                s_method = "GET";
                s_host = "www.google.com";
                s_test_header = NULL;
                l_s = l_profile->process(&l_event, l_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_host = NULL;
                s_method = "GET";
                s_header_content_length = NULL;
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                l_engine->shutdown();
                if(l_profile)
                {
                        delete l_profile;
                        l_profile = NULL;
                }
                if(l_pb)
                {
                        delete l_pb;
                        l_pb = NULL;
                }
                if(l_engine)
                {
                        delete l_engine;
                        l_engine = NULL;
                }
                if(l_geoip2_mmdb)
                {
                        delete l_geoip2_mmdb;
                        l_geoip2_mmdb = NULL;
                }
        }
}
