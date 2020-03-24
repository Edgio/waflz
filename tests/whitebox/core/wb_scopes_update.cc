//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_scopes_update.cc
//: \details: To test all entity updates in scopes
//: \author:  Revathi Sabanayagam
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
//: includes
//: ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/scopes_configs.h"
#include "waflz/scopes.h"
#include "waflz/engine.h"
#include "waflz/db/kycb_db.h"
//: ----------------------------------------------------------------------------
//: config
//: ----------------------------------------------------------------------------
#define SCOPE_ACL_JSON
//: ----------------------------------------------------------------------------
//: Test to update acl config
//: ----------------------------------------------------------------------------
TEST_CASE( "acl config update", "[acl config]" )
{
	    // -----------------------------------------
        // init
        // -----------------------------------------
		ns_waflz::engine* l_engine = new ns_waflz::engine();
		std::string l_geoip2_city_file("/../../../../tests/data/waf/db/GeoLite2-City.mmdb");
		std::string l_geoip2_asn_file("/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb");
		l_engine->set_geoip2_dbs(l_geoip2_city_file, l_geoip2_asn_file);
		l_engine->set_ruleset_dir("../../../../tests/data/waf/ruleset/");
		l_engine->init();
		ns_waflz::kv_db* l_db = reinterpret_cast<ns_waflz::kv_db*>(new ns_waflz::kycb_db());
		ns_waflz::scopes_configs* l_scopes_configs = new ns_waflz::scopes_configs(*l_engine, *l_db, false);
		l_scopes_configs->set_conf_dir("../../../../tests/data/waf/conf/");



}