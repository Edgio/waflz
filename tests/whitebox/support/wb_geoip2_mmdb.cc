//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_geoip2_mmdb.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    01/04/2018
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
//: cncludes
//: ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "waflz/profile.h"
#include "waflz/geoip2_mmdb.h"
#include "support/ndebug.h"
#include <unistd.h>
#include <string.h>
//: ----------------------------------------------------------------------------
//: kycb_db
//: ----------------------------------------------------------------------------
TEST_CASE( "maxminds geoip2 mmdb test", "[geoip2_mmdb]" ) {

        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
            //fprintf(stdout, "Current working dir: %s\n", l_cwd);
        }
        std::string l_geoip2_city_file = l_cwd;
        std::string l_geoip2_asn_file = l_cwd;
        l_geoip2_city_file += "/../../../../tests/data/waf/db/GeoLite2-City.mmdb";
        //l_geoip2_city_file += "/../tests/data/waf/db/GeoLite2-City.mmdb";
        l_geoip2_asn_file += "/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb";
        //l_geoip2_asn_file += "/../tests/data/waf/db/GeoLite2-ASN.mmdb";
        // -------------------------------------------------
        // bad init
        // -------------------------------------------------
        SECTION("validate bad init") {
                ns_waflz::geoip2_mmdb *l_geoip2_mmdb = new ns_waflz::geoip2_mmdb();
                int32_t l_s;
                l_s = l_geoip2_mmdb->init("/tmp/monkeys", "/tmp/bananas");
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_geoip2_mmdb)
                {
                        delete l_geoip2_mmdb;
                        l_geoip2_mmdb = NULL;
                }
        }
        // -------------------------------------------------
        // std tests
        // -------------------------------------------------
        SECTION("validate country code") {
                ns_waflz::geoip2_mmdb *l_geoip2_mmdb = new ns_waflz::geoip2_mmdb();
                int32_t l_s;
                // -----------------------------------------
                // init
                // -----------------------------------------
                l_s = l_geoip2_mmdb->init(l_geoip2_city_file, l_geoip2_asn_file);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // lookups
                // -----------------------------------------
                const char *l_buf;
                uint32_t l_buf_len;
                l_s = l_geoip2_mmdb->get_country(&l_buf,
                                                 l_buf_len,
                                                 "127.0.0.1",
                                                 strlen("127.0.0.1"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //NDBG_PRINT("CN: %.*s\n", l_buf_len, l_buf);
                REQUIRE((l_buf == NULL));
                l_s = l_geoip2_mmdb->get_country(&l_buf,
                                                 l_buf_len,
                                                 "45.249.212.124",
                                                 strlen("45.249.212.124"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //NDBG_PRINT("CN: %.*s\n", l_buf_len, l_buf);
                REQUIRE((strncasecmp(l_buf, "CN", l_buf_len) == 0));
                l_s = l_geoip2_mmdb->get_country(&l_buf,
                                                 l_buf_len,
                                                 "202.32.115.5",
                                                 strlen("202.32.115.5"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //NDBG_PRINT("CN: %.*s\n", l_buf_len, l_buf);
                REQUIRE((strncasecmp(l_buf, "JP", l_buf_len) == 0));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_geoip2_mmdb)
                {
                        delete l_geoip2_mmdb;
                        l_geoip2_mmdb = NULL;
                }
        }
        // -------------------------------------------------
        // std tests
        // -------------------------------------------------
        SECTION("validate asn") {
                ns_waflz::geoip2_mmdb *l_geoip2_mmdb = new ns_waflz::geoip2_mmdb();
                int32_t l_s;
                // -----------------------------------------
                // init
                // -----------------------------------------
                l_s = l_geoip2_mmdb->init(l_geoip2_city_file, l_geoip2_asn_file);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // lookups
                // -----------------------------------------
                const char *l_buf;
                uint32_t l_buf_len;
                uint32_t l_asn;
                l_s = l_geoip2_mmdb->get_asn(l_asn,
                                             "127.0.0.1",
                                             strlen("127.0.0.1"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //NDBG_PRINT("CN: %.*s\n", l_buf_len, l_buf);
                REQUIRE((l_asn == 0));
                l_s = l_geoip2_mmdb->get_asn(l_asn,
                                             "72.21.92.7",
                                             strlen("72.21.92.7"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //NDBG_PRINT("CN: %.*s\n", l_buf_len, l_buf);
                // edgecast!!!
                REQUIRE((l_asn == 15133));
                l_s = l_geoip2_mmdb->get_asn(l_asn,
                                             "172.217.5.206",
                                             strlen("172.217.5.206"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //NDBG_PRINT("CN: %.*s\n", l_buf_len, l_buf);
                // the googlss
                REQUIRE((l_asn == 15169));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_geoip2_mmdb)
                {
                        delete l_geoip2_mmdb;
                        l_geoip2_mmdb = NULL;
                }
        }
}
