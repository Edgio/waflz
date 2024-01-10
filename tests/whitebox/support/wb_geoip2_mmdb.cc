//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! cncludes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "waflz/geoip2_mmdb.h"
#include "waflz/rqst_ctx.h"
#include "support/ndebug.h"
#include <unistd.h>
#include <string.h>
//! ----------------------------------------------------------------------------
//! geoip2
//! ----------------------------------------------------------------------------
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
                // ips
                // -----------------------------------------
                ns_waflz::data_t l_ip_1;
                l_ip_1.m_data = "127.0.0.1";
                l_ip_1.m_len = 9;
                ns_waflz::data_t l_ip_2;
                l_ip_2.m_data = "45.249.212.124";
                l_ip_2.m_len = 14;
                ns_waflz::data_t l_ip_3;
                l_ip_3.m_data = "202.32.115.5";
                l_ip_3.m_len = 12;
                // -----------------------------------------
                // NOTE: for the test, waflz will return
                // an error - this is because the lite
                // mmdbs dont have is_anonymous_proxy.
                // as long as the other data is present, we
                // are good.
                // -----------------------------------------
                // -----------------------------------------
                // test lookup on ip 1
                // -----------------------------------------
                ns_waflz::geoip_data l_results;
                l_s = l_geoip2_mmdb->get_city_data(
                                       &l_results, &l_ip_1);
                REQUIRE((l_results.m_geo_cn2.m_data == NULL));
                // -----------------------------------------
                // test lookup on ip 2
                // -----------------------------------------
                l_s = l_geoip2_mmdb->get_city_data(
                                       &l_results, &l_ip_2);
                REQUIRE((strncasecmp(
                         l_results.m_geo_cn2.m_data,
                         "CN",
                         l_results.m_geo_cn2.m_len) == 0));
                REQUIRE(l_results.m_lat == 31.863900);
                REQUIRE(l_results.m_long == 117.280800);
                REQUIRE((strncasecmp(
                        l_results.m_src_sd1_iso.m_data,
                        "34",
                        l_results.m_src_sd1_iso.m_len) == 0));
                // -----------------------------------------
                // test lookup on ip 2
                // -----------------------------------------
                l_s = l_geoip2_mmdb->get_city_data(
                                       &l_results, &l_ip_3);
                REQUIRE((strncasecmp(
                         l_results.m_geo_cn2.m_data,
                         "JP",
                         l_results.m_geo_cn2.m_len) == 0));
                REQUIRE(l_results.m_lat == 35.690000);
                REQUIRE(l_results.m_long == 139.690000);
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
                // ips
                // -----------------------------------------
                ns_waflz::data_t l_ip_1;
                l_ip_1.m_data = "127.0.0.1";
                l_ip_1.m_len = 9;
                ns_waflz::data_t l_ip_2;
                l_ip_2.m_data = "72.21.92.7";
                l_ip_2.m_len = 10;
                ns_waflz::data_t l_ip_3;
                l_ip_3.m_data = "172.217.5.206";
                l_ip_3.m_len = 13;
                // -----------------------------------------
                // test lookup on ip 1
                // -----------------------------------------
                ns_waflz::geoip_data l_results;
                l_s = l_geoip2_mmdb->get_asn_data(
                                       &l_results, &l_ip_1);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_results.m_src_asn == 0));
                // -----------------------------------------
                // test lookup on ip 2
                // -----------------------------------------
                l_s = l_geoip2_mmdb->get_asn_data(
                                       &l_results, &l_ip_2);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_results.m_src_asn == 15133));
                // -----------------------------------------
                // test lookup on ip 2
                // -----------------------------------------
                l_s = l_geoip2_mmdb->get_asn_data(
                                       &l_results, &l_ip_3);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_results.m_src_asn == 15169));
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
        SECTION("validate full thing") {
                ns_waflz::geoip2_mmdb *l_geoip2_mmdb = new ns_waflz::geoip2_mmdb();
                int32_t l_s;
                // -----------------------------------------
                // init
                // -----------------------------------------
                l_s = l_geoip2_mmdb->init(l_geoip2_city_file, l_geoip2_asn_file);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // ips
                // -----------------------------------------
                ns_waflz::data_t l_ip;
                l_ip.m_data = "72.21.92.7";
                l_ip.m_len = 10;
                // -----------------------------------------
                // test lookup on ip
                // -----------------------------------------
                ns_waflz::geoip_data l_results;
                l_s = l_geoip2_mmdb->get_geo_data(
                                       &l_results, &l_ip);
                REQUIRE((l_results.m_src_asn == 15133));
                REQUIRE((strncasecmp(
                         l_results.m_geo_cn2.m_data,
                         "US",
                         l_results.m_geo_cn2.m_len) == 0));
                REQUIRE(l_results.m_lat == 37.751000);
                REQUIRE(l_results.m_long == -97.822000);
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
