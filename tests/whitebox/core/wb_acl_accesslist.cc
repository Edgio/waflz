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
#include "waflz/geoip2_mmdb.h"
#include "waflz/def.h"
#include "config.pb.h"
#include "event.pb.h"
#include "support/ndebug.h"
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
        // add policies
        // -----------------------------------------
        l_pb->add_policies("modsecurity_crs_21_protocol_anomalies.conf");
        l_pb->add_policies("modsecurity_crs_49_inbound_blocking.conf");
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
        ::waflz_pb::acl* l_ax = NULL;
        l_ax = l_pb->mutable_access_settings();
        ::waflz_pb::acl_lists_t* l_ax_ip = l_ax->mutable_ip();
        UNUSED(l_ax_ip);
        ::waflz_pb::acl_lists_t* l_ax_cntry = l_ax->mutable_country();
        UNUSED(l_ax_cntry);
        ::waflz_pb::acl_lists_t* l_ax_url = l_ax->mutable_url();
        UNUSED(l_ax_url);
        ::waflz_pb::acl_lists_t* l_ax_refr = l_ax->mutable_referer();
        UNUSED(l_ax_refr);
        return l_pb;
}
//: ----------------------------------------------------------------------------
//: profile acl tests
//: ----------------------------------------------------------------------------
TEST_CASE( "acl accesslist test", "[acl accesslist]" )
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
        // -----------------------------------------
        // geoip
        // -----------------------------------------
        std::string l_geoip2_city_file = l_cwd;
        std::string l_geoip2_asn_file = l_cwd;
        l_geoip2_city_file += "/../../../../tests/data/waf/db/GeoLite2-City.mmdb";
        l_geoip2_asn_file += "/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb";
        //--------------------------------------------------
        // acl
        // -------------------------------------------------
        SECTION("acl accesslist tests") {
                // -----------------------------------------
                // setup
                // -----------------------------------------
                ns_waflz::engine *l_engine = new ns_waflz::engine();
                l_engine->set_geoip2_dbs(l_geoip2_city_file, l_geoip2_asn_file);
                l_engine->set_ruleset_dir(l_rule_dir);
                int32_t l_s;
                l_s = l_engine->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
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
        }
}
