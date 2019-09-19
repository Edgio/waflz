//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_matched_data.cc
//: \details: TODO
//: \author:  James Cline
//: \date:    06/26/2017
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
#include "waflz/instances.h"
#include "waflz/instance.h"
#include "waflz/profile.h"
#include "waflz/engine.h"
#include "jspb/jspb.h"
#include "profile.pb.h"
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string>
#if 0
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_src_addr_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_uri[] = "243.49.2.0";
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_line_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "GET /800050/origin.testsuite.com/sec_arg_check/info.html?a=%27select%20*%20from%20test_5%27 HTTP/1.1";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_method_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "GET";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_protocol_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "HTTP/1.1";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_scheme_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "http";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_port_cb(uint32_t &a_val, void *a_ctx)
{
        a_val = 80;
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_uri_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "/800050/origin.testsuite.com/sec_arg_check/info.html?a=%27select%20*%20from%20test_5%27";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_query_str_long_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "mooooooooooooooooooooooooooooooooooooooooooooooooooooonnnnnnnnnnnnnnnnkkkkkkkkkkkkkkkkkkeeeeeeeeeeeeeeeyyyyyyyyyyssssss=100000000000000000000000000000000000000";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_query_str_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "a=%27select%20*%20from%20test_5%27";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t &a_val, void *a_ctx)
{
        a_val = 3;
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
#if 0
static int32_t get_rqst_header_w_key_cb(const char **ao_val,
                                        uint32_t &ao_val_len,
                                        void *a_ctx,
                                        const char *a_key,
                                        uint32_t a_key_len)
{
        //> Host: www.google.com
        //> User-Agent: curl/7.47.0
        //> Accept: */*
#if 0
        ns_is2::clnt_session *l_ctx = (ns_is2::clnt_session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *ao_val = NULL;
        ao_val_len = 0;
        ns_is2::kv_map_list_t::const_iterator i_h = l_rqst->get_headers().find(a_key);
        if(i_h != l_rqst->get_headers().end())
        {
                *ao_val = i_h->second.front().c_str();
                ao_val_len = i_h->second.front().length();
        }
#endif
        return 0;
}
#endif
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
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
//: ----------------------------------------------------------------------------
//: coordinator tests
//: ----------------------------------------------------------------------------
TEST_CASE( "dont_log_matched_data feature flag tests", "[profiles]" ) {

        char l_cwd[1024];
        if (getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
            //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        std::string l_conf_dir = l_cwd;
        std::string l_rule_dir = l_cwd;
        std::string l_geoip2_city_file = l_cwd;
        std::string l_geoip2_asn_file = l_cwd;
        l_conf_dir += "/../../../../tests/whitebox/data/waf/";
        //l_conf_dir += "/../tests/whitebox/data/waf/";
        l_rule_dir += "/../../../../tests/data/waf/ruleset/";
        //l_rule_dir += "/../tests/data/waf/ruleset/";
        l_geoip2_city_file += "/../../../../tests/data/waf/db/GeoLite2-City.mmdb";
        l_geoip2_asn_file += "/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb";
        // TODO FIX!!!
#if 0
        // -------------------------------------------------
        // Validate the feature flag is set properly when missing
        // -------------------------------------------------
        SECTION("missing dont_log_matched_data implies log matched data") {
                ns_waflz::instances *l_ix = new ns_waflz::instances();
		l_ix = new ns_waflz::instances();
		REQUIRE((l_ix != NULL));
		int32_t l_s;
		l_s = l_ix->init();
		REQUIRE((l_s == WAFLZ_STATUS_OK));
                int l_fd = open((l_conf_dir + "DEADDEAD-1001.waf.json").c_str(), O_RDONLY);
                REQUIRE((l_fd != -1));
                struct stat l_stat;
                int l_ret = fstat(l_fd, &l_stat);
                REQUIRE((l_ret != -1));
                char l_raw_config[l_stat.st_size];
                REQUIRE((read(l_fd, l_raw_config, l_stat.st_size) != -1));
                ns_waflz::profile l_profile;
                l_ret = l_profile.load_config(l_raw_config, l_stat.st_size);
                INFO(l_profile.get_err_msg());
                REQUIRE((l_ret == WAFLZ_STATUS_OK));
                REQUIRE((!l_profile.get_pb()->general_settings().dont_log_matched_data()));
        }
        // -------------------------------------------------
        // Validate the feature flag is set to True properly
        // -------------------------------------------------
        SECTION("true dont_log_matched_data implies dont log matched data") {
                ns_waflz::instances *l_ix = new ns_waflz::instances();
		l_ix = new ns_waflz::instances();
		REQUIRE((l_ix != NULL));
		int32_t l_s;
		l_s = l_ix->init();
		REQUIRE((l_s == WAFLZ_STATUS_OK));
                int l_fd = open((l_conf_dir + "DEADDEAD-1002.waf.json").c_str(), O_RDONLY);
                REQUIRE((l_fd != -1));
                struct stat l_stat;
                int l_ret = fstat(l_fd, &l_stat);
                REQUIRE((l_ret != -1));
                char l_raw_config[l_stat.st_size];
                REQUIRE((read(l_fd, l_raw_config, l_stat.st_size) != -1));
                ns_waflz::profile l_profile;
                l_ret = l_profile.load_config(l_raw_config, l_stat.st_size);
                INFO(l_profile.get_err_msg());
                REQUIRE((l_ret == WAFLZ_STATUS_OK));
                REQUIRE((l_profile.get_pb()->general_settings().dont_log_matched_data()));
        }
        // -------------------------------------------------
        // Validate the feature flag is set to False properly
        // -------------------------------------------------
        SECTION("false dont_log_matched_data implies log matched data") {
                ns_waflz::instances *l_ix = new ns_waflz::instances();
		l_ix = new ns_waflz::instances();
		REQUIRE((l_ix != NULL));
		int32_t l_s;
		l_s = l_ix->init();
		REQUIRE((l_s == WAFLZ_STATUS_OK));
                int l_fd = open((l_conf_dir + "DEADDEAD-1003.waf.json").c_str(), O_RDONLY);
                REQUIRE((l_fd != -1));
                struct stat l_stat;
                int l_ret = fstat(l_fd, &l_stat);
                REQUIRE((l_ret != -1));
                char l_raw_config[l_stat.st_size];
                REQUIRE((read(l_fd, l_raw_config, l_stat.st_size) != -1));
                ns_waflz::profile l_profile;
                l_ret = l_profile.load_config(l_raw_config, l_stat.st_size);
                INFO(l_profile.get_err_msg());
                REQUIRE((l_ret == WAFLZ_STATUS_OK));
                REQUIRE((!l_profile.get_pb()->general_settings().dont_log_matched_data()));
        }
        SECTION("missing dont_log_matched_data logs matched data") {
                // -----------------------------------------
                // touch geoip db file
                // -----------------------------------------
                int l_fd = open("/tmp/BOGUS_GEO_DATABASE.db", O_RDWR | O_CREAT | O_TRUNC,
                                                              S_IRUSR | S_IWUSR |
                                                              S_IRGRP | S_IWGRP |
                                                              S_IROTH | S_IWOTH);
                if(l_fd == -1)
                {
                        printf("error performing open. reason: %s\n", strerror(errno));
                }
                REQUIRE((l_fd != -1));
                close(l_fd);
                l_fd = -1;
                //set_trace(true);
                // -----------------------------------------
                // callbacks
                // -----------------------------------------
                ns_waflz::profile::s_geoip2_db = "/tmp/BOGUS_GEO_DATABASE.db";
                // waf
                ns_waflz::profile::s_get_rqst_src_addr_cb = get_rqst_src_addr_cb;
                ns_waflz::profile::s_get_rqst_uri_cb = get_rqst_uri_cb;
                ns_waflz::profile::s_get_rqst_query_str_cb = get_rqst_query_str_cb;
                ns_waflz::profile::s_get_rqst_line_cb = get_rqst_line_cb;
                ns_waflz::profile::s_get_rqst_scheme_cb = get_rqst_scheme_cb;
                ns_waflz::profile::s_get_rqst_port_cb = get_rqst_port_cb;
                ns_waflz::profile::s_get_rqst_method_cb = get_rqst_method_cb;
                ns_waflz::profile::s_get_rqst_protocol_cb = get_rqst_protocol_cb;
                ns_waflz::profile::s_get_rqst_header_size_cb = get_rqst_header_size_cb;
                ns_waflz::profile::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_cb;
                ns_waflz::profile::s_get_rqst_query_str_cb = get_rqst_query_str_long_cb;
                ns_waflz::instances *l_ix = new ns_waflz::instances();
                void *l_ctx = NULL;
		REQUIRE((l_ix != NULL));
		int32_t l_s;
		l_s = l_ix->init();
		REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_ix->finalize();
                l_fd = open((l_conf_dir + "DEADDEAD-1001.waf.json").c_str(), O_RDONLY);
                REQUIRE((l_fd != -1));
                struct stat l_stat;
                int l_ret = fstat(l_fd, &l_stat);
                REQUIRE((l_ret != -1));
                char l_raw_config[l_stat.st_size];
                REQUIRE((read(l_fd, l_raw_config, l_stat.st_size) != -1));
                ns_waflz::profile l_profile;
                l_profile.set_msx_server((server_rec*)l_ix->get_msx_server());
                l_ret = l_profile.load_config(l_raw_config, l_stat.st_size);
                INFO(l_profile.get_err_msg());
                REQUIRE((l_ret == WAFLZ_STATUS_OK));
                REQUIRE((!l_profile.get_pb()->general_settings().dont_log_matched_data()));
                // -----------------------------------------
                // process
                // -----------------------------------------
                l_ix->set_locking(true);
                waflz_pb::event *l_event = NULL;
                l_s = l_profile.process(&l_event, l_ctx);
                CAPTURE(l_profile.get_err_msg());
                REQUIRE((l_s != WAFLZ_STATUS_ERROR));
                CAPTURE(l_event);
                CAPTURE(l_event->ShortDebugString());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE(l_event->has_matched_data());
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                l_ix->shutdown();
                if(l_ix)
                {
                        delete l_ix;
                        l_ix = NULL;
                }
                if(l_event)
                {
                        delete l_event;
                        l_event = NULL;
                }
        }
        SECTION("true dont_log_matched_data logs matched data") {
                // -----------------------------------------
                // touch geoip db file
                // -----------------------------------------
                int l_fd = open("/tmp/BOGUS_GEO_DATABASE.db", O_RDWR | O_CREAT | O_TRUNC,
                                                              S_IRUSR | S_IWUSR |
                                                              S_IRGRP | S_IWGRP |
                                                              S_IROTH | S_IWOTH);
                if(l_fd == -1)
                {
                        printf("error performing open. reason: %s\n", strerror(errno));
                }
                REQUIRE((l_fd != -1));
                close(l_fd);
                l_fd = -1;
                //set_trace(true);
                // -----------------------------------------
                // callbacks
                // -----------------------------------------
                ns_waflz::profile::s_ruleset_dir = l_rule_dir;
                ns_waflz::profile::s_geoip2_db = "/tmp/BOGUS_GEO_DATABASE.db";
                // waf
                ns_waflz::profile::s_get_rqst_src_addr_cb = get_rqst_src_addr_cb;
                ns_waflz::profile::s_get_rqst_uri_cb = get_rqst_uri_cb;
                ns_waflz::profile::s_get_rqst_query_str_cb = get_rqst_query_str_cb;
                ns_waflz::profile::s_get_rqst_line_cb = get_rqst_line_cb;
                ns_waflz::profile::s_get_rqst_scheme_cb = get_rqst_scheme_cb;
                ns_waflz::profile::s_get_rqst_port_cb = get_rqst_port_cb;
                ns_waflz::profile::s_get_rqst_method_cb = get_rqst_method_cb;
                ns_waflz::profile::s_get_rqst_protocol_cb = get_rqst_protocol_cb;
                ns_waflz::profile::s_get_rqst_header_size_cb = get_rqst_header_size_cb;
                ns_waflz::profile::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_cb;
                ns_waflz::profile::s_get_rqst_query_str_cb = get_rqst_query_str_long_cb;
                ns_waflz::instances *l_ix = new ns_waflz::instances();
                void *l_ctx = NULL;
		REQUIRE((l_ix != NULL));
		int32_t l_s;
		l_s = l_ix->init();
		REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_ix->finalize();
                l_fd = open((l_conf_dir + "DEADDEAD-1002.waf.json").c_str(), O_RDONLY);
                REQUIRE((l_fd != -1));
                struct stat l_stat;
                int l_ret = fstat(l_fd, &l_stat);
                REQUIRE((l_ret != -1));
                char l_raw_config[l_stat.st_size];
                REQUIRE((read(l_fd, l_raw_config, l_stat.st_size) != -1));
                ns_waflz::profile l_profile;
                l_profile.set_msx_server((server_rec*)l_ix->get_msx_server());
                l_ret = l_profile.load_config(l_raw_config, l_stat.st_size);
                INFO(l_profile.get_err_msg());
                REQUIRE((l_ret == WAFLZ_STATUS_OK));
                REQUIRE((l_profile.get_pb()->general_settings().dont_log_matched_data()));
                // -----------------------------------------
                // process
                // -----------------------------------------
                l_ix->set_locking(true);
                waflz_pb::event *l_event = NULL;
                l_s = l_profile.process(&l_event, l_ctx);
                CAPTURE(l_profile.get_err_msg());
                REQUIRE((l_s != WAFLZ_STATUS_ERROR));
                CAPTURE(l_event);
                CAPTURE(l_event->ShortDebugString());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE(!l_event->has_matched_data());
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                l_ix->shutdown();
                if(l_ix)
                {
                        delete l_ix;
                        l_ix = NULL;
                }
                if(l_event)
                {
                        delete l_event;
                        l_event = NULL;
                }
        }
        SECTION("false dont_log_matched_data logs matched data") {
                // -----------------------------------------
                // touch geoip db file
                // -----------------------------------------
                int l_fd = open("/tmp/BOGUS_GEO_DATABASE.db", O_RDWR | O_CREAT | O_TRUNC,
                                                              S_IRUSR | S_IWUSR |
                                                              S_IRGRP | S_IWGRP |
                                                              S_IROTH | S_IWOTH);
                if(l_fd == -1)
                {
                        printf("error performing open. reason: %s\n", strerror(errno));
                }
                REQUIRE((l_fd != -1));
                close(l_fd);
                l_fd = -1;
                //set_trace(true);
                // -----------------------------------------
                // callbacks
                // -----------------------------------------
                ns_waflz::profile::s_ruleset_dir = l_rule_dir;
                ns_waflz::profile::s_geoip2_db = "/tmp/BOGUS_GEO_DATABASE.db";
                // waf
                ns_waflz::profile::s_get_rqst_src_addr_cb = get_rqst_src_addr_cb;
                ns_waflz::profile::s_get_rqst_uri_cb = get_rqst_uri_cb;
                ns_waflz::profile::s_get_rqst_query_str_cb = get_rqst_query_str_cb;
                ns_waflz::profile::s_get_rqst_line_cb = get_rqst_line_cb;
                ns_waflz::profile::s_get_rqst_scheme_cb = get_rqst_scheme_cb;
                ns_waflz::profile::s_get_rqst_port_cb = get_rqst_port_cb;
                ns_waflz::profile::s_get_rqst_method_cb = get_rqst_method_cb;
                ns_waflz::profile::s_get_rqst_protocol_cb = get_rqst_protocol_cb;
                ns_waflz::profile::s_get_rqst_header_size_cb = get_rqst_header_size_cb;
                ns_waflz::profile::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_cb;
                ns_waflz::profile::s_get_rqst_query_str_cb = get_rqst_query_str_long_cb;
                ns_waflz::instances *l_ix = new ns_waflz::instances();
                void *l_ctx = NULL;
		REQUIRE((l_ix != NULL));
		int32_t l_s;
		l_s = l_ix->init();
		REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_ix->finalize();
                l_fd = open((l_conf_dir + "DEADDEAD-1003.waf.json").c_str(), O_RDONLY);
                REQUIRE((l_fd != -1));
                struct stat l_stat;
                int l_ret = fstat(l_fd, &l_stat);
                REQUIRE((l_ret != -1));
                char l_raw_config[l_stat.st_size];
                REQUIRE((read(l_fd, l_raw_config, l_stat.st_size) != -1));
                ns_waflz::profile l_profile;
                l_profile.set_msx_server((server_rec*)l_ix->get_msx_server());
                l_ret = l_profile.load_config(l_raw_config, l_stat.st_size);
                INFO(l_profile.get_err_msg());
                REQUIRE((l_ret == WAFLZ_STATUS_OK));
                REQUIRE((!l_profile.get_pb()->general_settings().dont_log_matched_data()));
                // -----------------------------------------
                // process
                // -----------------------------------------
                l_ix->set_locking(true);
                waflz_pb::event *l_event = NULL;
                l_s = l_profile.process(&l_event, l_ctx);
                CAPTURE(l_profile.get_err_msg());
                REQUIRE((l_s != WAFLZ_STATUS_ERROR));
                CAPTURE(l_event);
                CAPTURE(l_event->ShortDebugString());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE(l_event->has_matched_data());
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                l_ix->shutdown();
                if(l_ix)
                {
                        delete l_ix;
                        l_ix = NULL;
                }
                if(l_event)
                {
                        delete l_event;
                        l_event = NULL;
                }
        }
#endif
}
