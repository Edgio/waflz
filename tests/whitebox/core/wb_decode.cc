//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_decode.cc
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
#include "core/decode.h"
#include "support/ndebug.h"
#include "support/string_util.h"
#include <string.h>
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef struct _entry {
        const char *m_in;
        const char *m_out;
        const uint32_t m_size;
} entry_t;
//: ----------------------------------------------------------------------------
//: parse
//: ----------------------------------------------------------------------------
TEST_CASE( "test parse", "[parse]" ) {
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("normalize") {
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"/pagead/osd.js?a='select * from testing'&b=c&c=d",
                         "/pagead/osd.js?a='select * from testing'&b=c&c=d"},
                        // 2.
                        {"/pagead/monkey/../banana",
                         "/pagead/banana"},
                        // 3.
                        {"/pagead/./././banana",
                         "/pagead/banana"},
                };
                uint32_t l_size = ARRAY_SIZE(l_vec);
                for(uint32_t i_p = 0; i_p < l_size; ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        const char *l_out = l_vec[i_p].m_out;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        l_s = ns_waflz::normalize_path(&l_buf, l_len, l_in, strlen(l_in), false);
                        //NDBG_PRINT("l_buf: %.*s\n", l_len, l_buf);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_len != 0));
                        REQUIRE((strncmp(l_buf, l_out, strlen(l_out)) == 0));
                        if(l_buf) { free(l_buf); l_buf = NULL; l_len = 0;}
                }
        }
        SECTION("parse query str"){
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"&utm_source=anonymous_email&&utm_medium=email&utm_term=ad_view&utm_campaign=vivamail&utm_content=gmail.com",
                         "utm_sourceanonymous_emailutm_mediumemailutm_termad_viewutm_campaignvivamailutm_contentgmail.com",
                          5},
                        // 2.
                        {"&a=&b=",
                         "ab",
                         2},
                        // 3.
                        {"=&b=a&=c",
                         "bac",
                         3},
                        {"a=b&c=d&e=f",
                         "abcdef",
                         3}
                };
                uint32_t l_size = ARRAY_SIZE(l_vec);
                for(uint32_t i_p = 0; i_p < l_size; ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        uint32_t l_invalid_cnt = 0;
                        ns_waflz::arg_list_t l_arg_list;
                        l_s = ns_waflz::parse_args(l_arg_list,
                                                   l_invalid_cnt,
                                                   l_in,
                                                   strlen(l_in),
                                                   '&');
                        std::string l_out;
                        for(ns_waflz::arg_list_t::iterator i_t = l_arg_list.begin();
                            i_t != l_arg_list.end();
                            ++i_t)
                        {
                                if(i_t->m_key)
                                {
                                        l_out.append(i_t->m_key);
                                }
                                if(i_t->m_val)
                                {
                                        l_out.append(i_t->m_val);
                                }
                        }
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_arg_list.size() == l_vec[i_p].m_size));
                        REQUIRE((strncmp(l_out.c_str(), l_vec[i_p].m_out, l_out.length()) == 0));
                }
        }
}
