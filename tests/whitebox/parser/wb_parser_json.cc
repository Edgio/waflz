//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_ac.cc
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
#include "waflz/rqst_ctx.h"
#include "parser/parser_json.h"
#include "support/ndebug.h"
#include <string.h>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define JSON_SHORT "{\"pets\": {\"cat\": \"fish\", \"dog\": \"bone\"}}"
#define JSON_LONG_FIELD_NAMES "{\"_data_1_0_bananaMonday_1088888_bananas_rc_Banana_Monkey_ttp_cat_fish_dog_koala_puid_XXX_XXXXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXX_XXXXXXXXXXX_XXXX_XXXXXXXXX_XXXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXXXX_XXXXXXXXXXXXX_status_strikeThroughText\":{\"url\":\"/data/1.0/Bananas/8888888/monkeys?rc=Banana_Monkeez&ttp=a_b_c_d_e&banana=AAAAABBBCCCCCDDDDD&monkeez=2019_01_01_2019_01_01&bananas=1_2&rn=2&fields=bananaMonkeez,complete,bananasMonkey,bananaMonkey&bananaMonkeez=data,bananas,bananaMonkeez,catDogs,catDogFish,status,wangWangWang\"}}"
//: ----------------------------------------------------------------------------
//: json parse
//: ----------------------------------------------------------------------------
TEST_CASE( "json parse basic test", "[json_parse_basic]" ) {
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("json parse basic") {
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 8096, true);
                ns_waflz::parser_json *l_p_json = new ns_waflz::parser_json(l_rqst_ctx);
                l_rqst_ctx->m_body_parser = l_p_json;
                int32_t l_s;
                l_s = l_p_json->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_json->process_chunk(JSON_SHORT, strlen(JSON_SHORT));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_rqst_ctx->m_body_arg_list.size() == 2));
                uint32_t i_arg = 0;
                for(ns_waflz::arg_list_t::const_iterator i_q = l_rqst_ctx->m_body_arg_list.begin();
                    i_q != l_rqst_ctx->m_body_arg_list.end();
                    ++i_q, ++i_arg)
                {
                        //NDBG_OUTPUT(": [%d]%.*s: [%d]%.*s\n",
                        //            i_q->m_key_len, i_q->m_key_len, i_q->m_key,
                        //            i_q->m_val_len, i_q->m_val_len, i_q->m_val);
                        switch(i_arg)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_q->m_key, "pets.cat", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "fish", i_q->m_val_len) == 0));
                                break;
                        }
                        case 1:
                        {
                                REQUIRE((strncmp(i_q->m_key, "pets.dog", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "bone", i_q->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // long field names
        // -------------------------------------------------
        SECTION("json parse long field names") {
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 8096, true);
                ns_waflz::parser_json *l_p_json = new ns_waflz::parser_json(l_rqst_ctx);
                l_rqst_ctx->m_body_parser = l_p_json;
                int32_t l_s;
                l_s = l_p_json->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_json->process_chunk(JSON_LONG_FIELD_NAMES, strlen(JSON_LONG_FIELD_NAMES));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_rqst_ctx->m_body_arg_list.size() == 1));
                uint32_t i_arg = 0;
                for(ns_waflz::arg_list_t::const_iterator i_q = l_rqst_ctx->m_body_arg_list.begin();
                    i_q != l_rqst_ctx->m_body_arg_list.end();
                    ++i_q, ++i_arg)
                {
                        switch(i_arg)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_q->m_key, "_data_1_0_bananaMonday_1088888_bananas_rc_Banana_Monkey_ttp_cat_fish_dog_koala_puid_XXX_XXXXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXX_XXXXXXXXXXX_XXXX_XXXXXXXXX_XXXXX.url", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "/data/1.0/Bananas/8888888/monkeys?rc=Banana_Monkeez&ttp=a_b_c_d_e&banana=AAAAABBBCCCCCDDDDD&monkeez=2019_01_01_2019_01_01&bananas=1_2&rn=2&fields=bananaMonkeez,complete,bananasMonkey,bananaMonkey&bananaMonkeez=data,bananas,bananaMonkeez,catDogs,catDogFish,status,wangWangWang", i_q->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
}
