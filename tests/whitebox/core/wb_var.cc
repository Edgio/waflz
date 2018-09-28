//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_var.cc
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
#include "core/var.h"
#include "support/ndebug.h"
#include <string.h>
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
        static const char s_line[] = "GET /800050/origin.testsuite.com/sec_arg_check/info.html?you=crazy&screws=loose HTTP/1.1";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_method_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "GETZ";
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
static int32_t get_rqst_url_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "bananas.com/800050/origin.testsuite.com/sec_arg_check/info.html?you=crazy&screws=loose";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_uri_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "/800050/origin.testsuite.com/sec_arg_check/info.html?you=crazy&screws=loose";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_path_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "/800050/origin.testsuite.com/sec_arg_check/info.html";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_query_str_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "you=crazy&screws=loose";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_body_str_cb
//: ----------------------------------------------------------------------------
#define _RQST_BODY_JSON "{\"monkeys\": \"bananas\", \"koalas\": \"fruitloops\", \"seamonkeys\": \"plankton\"}"
#define _RQST_BODY_XML "<monkeys><gorilla>coco</gorilla><mandrill>dooby</mandrill><baboon>groovy</baboon></monkeys>"
static const char *g_body_str = _RQST_BODY_JSON;
static int32_t get_rqst_body_str_cb(char *ao_data,
                                    uint32_t &ao_data_len,
                                    bool &ao_is_eos,
                                    void *a_ctx,
                                    uint32_t a_to_read)
{
        ao_data_len = strlen(g_body_str);
        memcpy(ao_data, g_body_str, ao_data_len);
        ao_is_eos = true;
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_header_size_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t &a_val, void *a_ctx)
{
        a_val = 6;
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_header_w_idx_cb
//: ----------------------------------------------------------------------------
static const char *g_header_user_agent = "my_cool_user_agent";
static const char *g_header_accept = "my_cool_accept_value";
static const char *g_header_referer = "my_cool_referer_value";
static const char *g_header_cookie = "__cookie_a=a_value; __cookie_b=b_value; __cookie_c=c_value;";
#define _RQST_CONTENT_TYPE_JSON "application/json"
#define _RQST_CONTENT_TYPE_XML "text/xml"
static const char *g_header_content_type = _RQST_CONTENT_TYPE_JSON;
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
        static char s_cl[16];
        switch(a_idx)
        {
        case 0:
        {
                *ao_key = "User-Agent";
                ao_key_len = strlen("User-Agent");
                *ao_val = g_header_user_agent;
                ao_val_len = strlen(g_header_user_agent);
                break;
        }
        case 1:
        {
                *ao_key = "Accept";
                ao_key_len = strlen("Accept");
                *ao_val = g_header_accept;
                ao_val_len = strlen(g_header_accept);
                break;
        }
        case 2:
        {
                *ao_key = "Referer";
                ao_key_len = strlen("Referer");
                *ao_val = g_header_referer;
                ao_val_len = strlen(g_header_referer);
                break;
        }
        case 3:
        {
                *ao_key = "Cookie";
                ao_key_len = strlen("Cookie");
                *ao_val = g_header_cookie;
                ao_val_len = strlen(g_header_cookie);
                break;
        }
        case 4:
        {
                *ao_key = "Content-Type";
                ao_key_len = strlen("Content-Type");
                *ao_val = g_header_content_type;
                ao_val_len = strlen(g_header_content_type);
                break;
        }
        case 5:
        {
                *ao_key = "Content-Length";
                ao_key_len = strlen("Content-Length");
                snprintf(s_cl, 16, "%d", (int)strlen(g_body_str));
                *ao_val = s_cl;
                ao_val_len = strlen(s_cl);
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
//: parse
//: ----------------------------------------------------------------------------
TEST_CASE( "test var", "[var]" ) {
        ns_waflz::init_var_cb_vector();
        ns_waflz::rqst_ctx::s_get_rqst_src_addr_cb = get_rqst_src_addr_cb;
        ns_waflz::rqst_ctx::s_get_rqst_url_cb = get_rqst_url_cb;
        ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_cb;
        ns_waflz::rqst_ctx::s_get_rqst_path_cb = get_rqst_path_cb;
        ns_waflz::rqst_ctx::s_get_rqst_query_str_cb = get_rqst_query_str_cb;
        ns_waflz::rqst_ctx::s_get_rqst_line_cb = get_rqst_line_cb;
        ns_waflz::rqst_ctx::s_get_rqst_scheme_cb = get_rqst_scheme_cb;
        ns_waflz::rqst_ctx::s_get_rqst_port_cb = get_rqst_port_cb;
        ns_waflz::rqst_ctx::s_get_rqst_method_cb = get_rqst_method_cb;
        ns_waflz::rqst_ctx::s_get_rqst_protocol_cb = get_rqst_protocol_cb;
        ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_cb;
        ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_cb;
        ns_waflz::rqst_ctx::s_get_rqst_body_str_cb = get_rqst_body_str_cb;
        ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(1024, true);
        ns_waflz::pcre_list_t l_il_query;
        ns_waflz::pcre_list_t l_il_header;
        ns_waflz::pcre_list_t l_il_cookie;
        // -------------------------------------------------
        // *************************************************
        //         Content-Type --> parser map
        // *************************************************
        // -------------------------------------------------
        ns_waflz::ctype_parser_map_t l_ctype_parser_map;
        l_ctype_parser_map["application/x-www-form-urlencoded"] = ns_waflz::PARSER_URL_ENCODED;
        l_ctype_parser_map["text/xml"]                          = ns_waflz::PARSER_XML;
        l_ctype_parser_map["application/xml"]                   = ns_waflz::PARSER_XML;
        l_ctype_parser_map["application/json"]                  = ns_waflz::PARSER_JSON;
        l_ctype_parser_map["multipart/form-data"]               = ns_waflz::PARSER_MULTIPART;
        l_rqst_ctx->init_phase_1(NULL, l_il_query, l_il_header, l_il_cookie);
        l_rqst_ctx->init_phase_2(l_ctype_parser_map, NULL);
        // -------------------------------------------------
        // ARGS
        // -------------------------------------------------
        SECTION("ARGS") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 5));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 2:
                        {
                                REQUIRE((strncmp(i_a->m_key, ".monkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "bananas", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value(".seamonkeys");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, ".seamonkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "plankton", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // ARGS_NAMES
        // -------------------------------------------------
        SECTION("ARGS_NAMES") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS_NAMES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS_NAMES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 5));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 2:
                        {
                                REQUIRE((strncmp(i_a->m_key, ".monkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, ".monkeys", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value(".seamonkeys");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, ".seamonkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, ".seamonkeys", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // ARGS_GET
        // -------------------------------------------------
        SECTION("ARGS_GET") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS_GET);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS_GET);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 2));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 1:
                        {
                                REQUIRE((strncmp(i_a->m_key, "screws", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "loose", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("you");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "you", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "crazy", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // ARGS_GET_NAMES
        // -------------------------------------------------
        SECTION("ARGS_GET_NAMES") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS_GET_NAMES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS_GET_NAMES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 2));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 1:
                        {
                                REQUIRE((strncmp(i_a->m_key, "screws", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "screws", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("you");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "you", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "you", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // ARGS_POST
        // -------------------------------------------------
        SECTION("ARGS_POST") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS_POST);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS_POST);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 3));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, ".monkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "bananas", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value(".seamonkeys");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, ".seamonkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "plankton", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // ARGS_POST_NAMES
        // -------------------------------------------------
        SECTION("ARGS_POST_NAMES") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS_POST_NAMES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS_POST_NAMES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 3));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, ".monkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, ".monkeys", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value(".seamonkeys");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, ".seamonkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, ".seamonkeys", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // ARGS_COMBINED_SIZE
        // -------------------------------------------------
        SECTION("ARGS_COMBINED_SIZE") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS_COMBINED_SIZE);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS_COMBINED_SIZE);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "ARGS_COMBINED_SIZE", i_a->m_key_len) == 0));
                                REQUIRE((i_a->m_val_len == 70));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // QUERY_STRING
        // -------------------------------------------------
        SECTION("QUERY_STRING") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_QUERY_STRING);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_QUERY_STRING);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "QUERY_STRING", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "you=crazy&screws=loose", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_BASENAME
        // -------------------------------------------------
        SECTION("REQUEST_BASENAME") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_BASENAME);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_BASENAME);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "REQUEST_BASENAME", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "info.html", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_FILENAME
        // -------------------------------------------------
        SECTION("REQUEST_FILENAME") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_FILENAME);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_FILENAME);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "REQUEST_FILENAME", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "/800050/origin.testsuite.com/sec_arg_check/info.html", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_COOKIES
        // -------------------------------------------------
        SECTION("REQUEST_COOKIES") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_COOKIES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_COOKIES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 3));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 1:
                        {
                                REQUIRE((strncmp(i_a->m_key, "__cookie_b", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "b_value", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("__cookie_c");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "__cookie_c", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "c_value", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_COOKIES_NAMES
        // -------------------------------------------------
        SECTION("REQUEST_COOKIES_NAMES") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_COOKIES_NAMES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_COOKIES_NAMES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 3));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 1:
                        {
                                REQUIRE((strncmp(i_a->m_key, "__cookie_b", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "__cookie_b", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("__cookie_c");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "__cookie_c", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "__cookie_c", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_HEADERS
        // -------------------------------------------------
        SECTION("REQUEST_HEADERS") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_HEADERS);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_HEADERS);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 6));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 1:
                        {
                                REQUIRE((strncmp(i_a->m_key, "Accept", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "my_cool_accept_value", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("Referer");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "Referer", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "my_cool_referer_value", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_HEADERS_NAMES
        // -------------------------------------------------
        SECTION("REQUEST_HEADERS_NAMES") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_HEADERS_NAMES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_HEADERS_NAMES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 6));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 1:
                        {
                                REQUIRE((strncmp(i_a->m_key, "Accept", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "Accept", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("Referer");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "Referer", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "Referer", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_LINE
        // -------------------------------------------------
        SECTION("REQUEST_LINE") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_LINE);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_LINE);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "REQUEST_LINE", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "GET /800050/origin.testsuite.com/sec_arg_check/info.html?you=crazy&screws=loose HTTP/1.1", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_METHOD
        // -------------------------------------------------
        SECTION("REQUEST_METHOD") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_METHOD);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_METHOD);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "REQUEST_METHOD", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "GETZ", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_PROTOCOL
        // -------------------------------------------------
        SECTION("REQUEST_PROTOCOL") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_PROTOCOL);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_PROTOCOL);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "REQUEST_PROTOCOL", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "HTTP/1.1", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_URI
        // -------------------------------------------------
        SECTION("REQUEST_URI") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_URI);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_URI);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "REQUEST_URI", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "/800050/origin.testsuite.com/sec_arg_check/info.html?you=crazy&screws=loose", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_URI_RAW
        // -------------------------------------------------
        SECTION("REQUEST_URI_RAW") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_URI_RAW);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_URI_RAW);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "REQUEST_URI_RAW", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "bananas.com/800050/origin.testsuite.com/sec_arg_check/info.html?you=crazy&screws=loose", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // TX
        // -------------------------------------------------
        SECTION("TX") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_TX);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_TX);
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("pAnDAs");
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_rqst_ctx->m_cx_tx_map["MONKEYS"] = "BANANAS";
                l_rqst_ctx->m_cx_tx_map["PANDAS"] = "TREES";
                l_rqst_ctx->m_cx_tx_map["FLEAS"] = "DOGS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "PANDAS", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "TREES", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // MATCHED_VAR
        // -------------------------------------------------
        SECTION("MATCHED_VAR") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_MATCHED_VAR);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_MATCHED_VAR);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_rqst_ctx->m_cx_matched_var_name = "MONKEYS";
                l_rqst_ctx->m_cx_matched_var = "BANANAS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "MONKEYS", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "BANANAS", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // MATCHED_VARS
        // -------------------------------------------------
        SECTION("MATCHED_VARS") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_MATCHED_VARS);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_MATCHED_VARS);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_rqst_ctx->m_cx_matched_var_name = "MONKEYS";
                l_rqst_ctx->m_cx_matched_var = "BANANAS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "MONKEYS", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "BANANAS", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // MATCHED_VAR_NAME
        // -------------------------------------------------
        SECTION("MATCHED_VAR_NAME") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_MATCHED_VAR_NAME);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_MATCHED_VAR_NAME);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_rqst_ctx->m_cx_matched_var_name = "MONKEYS";
                l_rqst_ctx->m_cx_matched_var = "BANANAS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "MONKEYS", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "MONKEYS", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // MATCHED_VAR_NAME
        // -------------------------------------------------
        SECTION("MATCHED_VARS_NAMES") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_MATCHED_VARS_NAMES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_MATCHED_VARS_NAMES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_rqst_ctx->m_cx_matched_var_name = "MONKEYS";
                l_rqst_ctx->m_cx_matched_var = "BANANAS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "MONKEYS", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "MONKEYS", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // XML
        // -------------------------------------------------
        SECTION("XML") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_XML);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_XML);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                g_body_str = _RQST_BODY_XML;
                g_header_content_type = _RQST_CONTENT_TYPE_XML;
                l_rqst_ctx->m_content_type_list.clear();
                l_rqst_ctx->init_phase_1(NULL, l_il_query, l_il_header, l_il_cookie);
                l_rqst_ctx->init_phase_2(l_ctype_parser_map, NULL);
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "XML", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "[XML document tree]", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("/monkeys/mandrill");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "/monkeys/mandrill", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "dooby", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // reset
                // -----------------------------------------
                g_body_str = _RQST_BODY_JSON;
                g_header_content_type = _RQST_CONTENT_TYPE_JSON;
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQBODY_ERROR
        // -------------------------------------------------
        SECTION("REQBODY_ERROR") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQBODY_ERROR);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQBODY_ERROR);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                g_body_str = _RQST_BODY_JSON;
                // Set incorrect type to generate parsing error
                g_header_content_type = _RQST_CONTENT_TYPE_XML;
                l_rqst_ctx->m_content_type_list.clear();
                l_rqst_ctx->init_phase_1(NULL, l_il_query, l_il_header, l_il_cookie);
                l_rqst_ctx->init_phase_2(l_ctype_parser_map, NULL);
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "REQBODY_ERROR", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "1", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // reset
                // -----------------------------------------
                g_body_str = _RQST_BODY_JSON;
                g_header_content_type = _RQST_CONTENT_TYPE_JSON;
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_BODY
        // -------------------------------------------------
        SECTION("REQUEST_BODY") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_BODY);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_BODY);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "REQUEST_BODY", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, g_body_str, i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REMOTE_ADDR
        // -------------------------------------------------
        SECTION("REMOTE_ADDR") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REMOTE_ADDR);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REMOTE_ADDR);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_a->m_key, "REMOTE_ADDR", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "243.49.2.0", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
}
