//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_file_util.cc
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
//: Includes
//: ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "support/string_util.h"
#include "support/kv_map_list.h"
#include <string>
#include <string.h>
//: ----------------------------------------------------------------------------
//: convert_hex_to_uint
//: ----------------------------------------------------------------------------
TEST_CASE( "convert hex to uint", "[convert_hex_to_uint]" ) {

        SECTION("Verify basic") {
                int32_t l_s = 0;
                uint64_t l_id = 0;
                l_s = ns_waflz::convert_hex_to_uint(l_id, "DEADDEAD");
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_id == 3735936685));
                l_s = ns_waflz::convert_hex_to_uint(l_id, "0050");
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_id == 80));
        }
        SECTION("Verify failures") {
                int32_t l_s = 0;
                uint64_t l_id = 0;
                l_s = ns_waflz::convert_hex_to_uint(l_id, "RAT00DEADFART");
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
        }
}
//: ----------------------------------------------------------------------------
//: parse cookie
//: ----------------------------------------------------------------------------
TEST_CASE( "parse cookie", "[parse_cookie]" ) {

        SECTION("Verify basic") {
                int32_t l_s = 0;
                ns_waflz::kv_map_list_t l_kv_map_list;
                const char l_cookie_str[] = " abc= =123  ;def;;;";
                l_s = ns_waflz::parse_cookie_str(l_kv_map_list, l_cookie_str, sizeof(l_cookie_str));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_kv_map_list.size() == 2));
                ns_waflz::kv_map_list_t::iterator i_k;
                uint32_t i_k_idx = 0;
                // -----------------------------------------
                // Example 'cookie: abc= =123  ;def;;;'
                //  - key='abc', val='123'
                //  - key='def', val=''
                // -----------------------------------------
                for(i_k = l_kv_map_list.begin(); i_k != l_kv_map_list.end(); ++i_k, ++i_k_idx)
                {
                        if(i_k_idx == 0)
                        {
                                REQUIRE((i_k->first == "abc"));
                                REQUIRE((i_k->second.size() == 1));
                                // TODO -known issue with trailing whitespace in values.
                                REQUIRE((i_k->second.front() == "123"));
                        }
                        else if(i_k_idx == 1)
                        {
                                REQUIRE((i_k->first == "def"));
                                REQUIRE((i_k->second.size() == 1));
                                REQUIRE((i_k->second.front().empty()));
                        }
                }
        }
}
// -----------------------------------------------------------------------------
// TODO add tests...
// -----------------------------------------------------------------------------
#if 0
TEST(http_message, test_cookies_parsing_simple)
{
        http_message msg;
        msg.get_headers().add("Cookie", "id=1234567890; data=x=1234567890");
        EXPECT_SUBEQ("1234567890", msg.get_cookie("id"));
        EXPECT_SUBEQ("x=1234567890", msg.get_cookie("data"));
        EXPECT_SUBEQ("", msg.get_cookie("mising"));
}
TEST(http_message, test_cookies_parsing_spaces)
{
        http_message msg;
        msg.get_headers().add("Cookie", " id=1122334455 ;   data=_1234567890  ;");
        EXPECT_SUBEQ("1122334455", msg.get_cookie("id"));
        EXPECT_SUBEQ("_1234567890", msg.get_cookie("data"));
}

TEST(http_message, test_cookies_parsing_single)
{
        // FIXME: cookie names are separated by a semicolon and space
        http_message msg;
        msg.get_headers().add("Cookie", "   user_id=1122334455  ");
        EXPECT_SUBEQ("1122334455", msg.get_cookie("user_id"));
}

TEST(http_message, test_cookies_parsing_multiple)
{
        http_message msg;
        msg.get_headers().add("Cookie", "id=1122334455; data=_1234567890; same=thing1; Name");
        msg.get_headers().add( "Cookie", "id2=1122334455; data2=_1234567890; same=thing2; ");
        EXPECT_SUBEQ("1122334455", msg.get_cookie("id"));
        EXPECT_SUBEQ("1122334455", msg.get_cookie("id2"));
        EXPECT_SUBEQ("_1234567890", msg.get_cookie("data"));
        EXPECT_SUBEQ("_1234567890", msg.get_cookie("data2"));
        // FIXME: this is weird behavior, we should keep dups
        EXPECT_SUBEQ("thing1, thing2", msg.get_cookie("same"));
        EXPECT_SUBEQ("", msg.get_cookie("Name"));
}
// Only space, semicolon, and comma need be url encoded
TEST(http_message, test_cookies_parsing_multiple_urlencoded)
{
        http_message msg;
        msg.get_headers().add("Cookie",
                              "optimizelySegments=%7B%22175404620%22%3A%22false%22%2C%22175262621%22%3A%22ff%22%2C%22173979470%22%3A%22referral%22%2C%22175460039%22%3A%22none%22%2C%22170962340%22%3A%22false%22%2C%22171657961%22%3A%22ff%22%2C%22172148679%22%3A%22none%22%2C%22172265329%22%3A%22direct%22%7D; optimizelyEndUserId=oeu1386626592696r0.8821292246704734; "
                              "optimizelyBuckets=%7B%7D; CNNMoneyEdition=domestic; s_vi=[CS]v1|29531F11851D3440-4000013620002036[CE]; __qseg=Q_D|Q_T|Q_12105|Q_249|Q_578|Q_234|Q_242|Q_240|Q_2900|Q_291|Q_1758|Q_446|Q_232|Q_27466; __qca=P0-421090605-1386626595267; __unam=3715f77-142d962bd52-14bfe1c7-1; CG=US:CA:Santa+Monica; ug=52a63e2101cccf0a3c6b803b640417f4; ugs=1; optimizelyPendingLogEvents=%5B%5D; SelectedEdition=www; s_cc=true; s_fid=4769B8D247F43D02-1BC6A77455210E63; s_sq=cnn-adbp-domestic%3D%2526pid%253Dhttp%25253A%25252F%25252Fwww.cnn.com%25252F%2526oid%253Dhttp%25253A%25252F%25252Fwww.cnn.com%25252FUS%25252F%25253Fhpt%25253Dsitenav%2526ot%253DA; rsi_segs_ttn=A09801_10001|A09801_10313|A09801_0; __vrf=1402101846855nGAhnfY8cFv6rIieKluEHXnxDt9CkfhS; _cb_ls=1; _chartbeat2=BFg6GkBmYYDOBWDQcy.1402101846974.1402101846974.1; _chartbeat_uuniq=3; s_ppv=22; __vrl=http%3A%2F%2Fwww.cnn.com%2FUS%2F%3Fhpt%3Dsitenav; __vry=0; __vru=http%3A%2F%2Fwww.cnn.com%2F; __vrid=6; __vrm=573_151_1797; _chartbeat5=552,135,%2F,http%3A%2F%2Fwww.cnn.com%2FUS%2F%3Fhpt%3Dsitenav\r\n");

        EXPECT_SUBEQ("%7B%22175404620%22%3A%22false%22%2C%22175262621%22%3A%22ff%22%2C%22173979470%22%3A%22referral%22%2C%22175460039%22%3A%22none%22%2C%22170962340%22%3A%22false%22%2C%22171657961%22%3A%22ff%22%2C%22172148679%22%3A%22none%22%2C%22172265329%22%3A%22direct%22%7D",
                     msg.get_cookie("optimizelySegments"));
        EXPECT_SUBEQ("%7B%7D", msg.get_cookie("optimizelyBuckets"));
        EXPECT_SUBEQ("domestic", msg.get_cookie("CNNMoneyEdition"));
        EXPECT_SUBEQ("[CS]v1|29531F11851D3440-4000013620002036[CE]", msg.get_cookie("s_vi"));
        EXPECT_SUBEQ("Q_D|Q_T|Q_12105|Q_249|Q_578|Q_234|Q_242|Q_240|Q_2900|Q_291|Q_1758|Q_446|Q_232|Q_27466", msg.get_cookie("__qseg"));
        EXPECT_SUBEQ("P0-421090605-1386626595267", msg.get_cookie("__qca"));
        EXPECT_SUBEQ("3715f77-142d962bd52-14bfe1c7-1", msg.get_cookie("__unam"));
        EXPECT_SUBEQ("oeu1386626592696r0.8821292246704734", msg.get_cookie("optimizelyEndUserId"));
}
TEST(http_message, test_multi_value_header)
{
        http_message msg;
        http_headers& headers = msg.get_headers();
        EXPECT_SUBEQ("", headers["Set-Cookie"]);
        headers.add("Set-Cookie", "first cookie", false);
        EXPECT_SUBEQ("first cookie", headers["Set-Cookie"]);
        EXPECT_SUBEQ("first cookie", headers[0]->value);
        headers.add("Set-Cookie", "second cookie", false);
        EXPECT_SUBEQ("first cookie\r\nSet-Cookie: second cookie", headers["Set-Cookie"]);
        headers.add("Set-Cookie", "third cookie", false);
        EXPECT_SUBEQ("first cookie\r\nSet-Cookie: second cookie\r\nSet-Cookie: third cookie", headers["Set-Cookie"]);
}
TEST(http_message, test_status_code_accessors)
{
        http_message msg;
        msg.set_status_code(200);
        EXPECT_EQ(200, msg.get_status_code());
}
TEST(http_message, test_split_cookie)
{
        {
                http_message msg;
                msg.get_headers().add("Cookie",
                                      "key1=val1; key2=val2; key3");
                EXPECT_SUBEQ("val1", msg.get_cookie("key1"));
                EXPECT_SUBEQ("val2", msg.get_cookie("key2"));
                EXPECT_SUBEQ("", msg.get_cookie("key3"));
                EXPECT_FALSE(msg.get_cookie("key3").is_set());
        }
        {
                http_message msg;
                msg.get_headers().add("Cookie",
                                      "key1=val1=val2; =;; key3=val3");
                EXPECT_SUBEQ("val1=val2", msg.get_cookie("key1"));
                EXPECT_SUBEQ("val3", msg.get_cookie("key3"));
                EXPECT_SUBEQ("", msg.get_cookie(";"));
                EXPECT_EQ(size_t(2), msg.get_cookie_count());
        }
        {
                http_message msg;
                msg.get_headers().add("Cookie",
                                      "=; ; ;;   ==; ; ;;;; =;=;==; ;=== == ;; ==a;= ;= ;= ==");
                EXPECT_EQ(size_t(1), msg.get_cookie_count());

                subbuffer cookie1 = msg.get_cookie("a");
                EXPECT_FALSE(cookie1.is_set());
        }
        {
                http_message msg;
                msg.get_headers().add("Cookie", "");
                EXPECT_EQ(size_t(0), msg.get_cookie_count());
        }
        {
                http_message msg;
                msg.get_headers().add("Cookie", " =; "); //  k v(empty)
                EXPECT_EQ(size_t(0), msg.get_cookie_count());
        }
        {
                http_message msg;
                msg.get_headers().add("Cookie", "km_uq_=; PROMOID=3520;km_uq2==;km_uq3= ;km_uq4=\t;");
                EXPECT_EQ(size_t(5), msg.get_cookie_count());
                EXPECT_SUBEQ("", msg.get_cookie("km_uq_"));
                EXPECT_SUBEQ("3520", msg.get_cookie("PROMOID"));
                EXPECT_SUBEQ("", msg.get_cookie("km_uq2"));
                EXPECT_SUBEQ("", msg.get_cookie("km_uq3"));
                EXPECT_SUBEQ("", msg.get_cookie("km_uq4"));
        }
        {
                http_message msg;
                msg.get_headers().add("Cookie", " abc= =123  ;def;;;");
                EXPECT_EQ(size_t(2), msg.get_cookie_count());
                EXPECT_SUBEQ("123", msg.get_cookie("abc"));
                EXPECT_SUBEQ("", msg.get_cookie("def"));
        }
}
#endif
