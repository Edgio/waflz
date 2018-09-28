//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    rqst_ctx.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    01/19/2018
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
#include "waflz/def.h"
#include "waflz/waf.h"
#include "waflz/rqst_ctx.h"
#include "core/decode.h"
#include "support/ndebug.h"
#include "op/regex.h"
#include "support/string_util.h"
#include "parser/parser_url_encoded.h"
#include "parser/parser_xml.h"
#include "parser/parser_json.h"
#include <stdlib.h>
#include <string.h>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define _DEFAULT_BODY_ARG_LEN_CAP 4096
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: callbacks
//: ----------------------------------------------------------------------------
get_rqst_data_cb_t rqst_ctx::s_get_rqst_src_addr_cb = NULL;
get_rqst_data_cb_t rqst_ctx::s_get_rqst_host_cb = NULL;
get_rqst_data_size_cb_t rqst_ctx::s_get_rqst_port_cb = NULL;
get_rqst_data_cb_t rqst_ctx::s_get_rqst_scheme_cb = NULL;
get_rqst_data_cb_t rqst_ctx::s_get_rqst_protocol_cb = NULL;
get_rqst_data_cb_t rqst_ctx::s_get_rqst_line_cb = NULL;
get_rqst_data_cb_t rqst_ctx::s_get_rqst_method_cb = NULL;
get_rqst_data_cb_t rqst_ctx::s_get_rqst_url_cb = NULL;
get_rqst_data_cb_t rqst_ctx::s_get_rqst_uri_cb = NULL;
get_rqst_data_cb_t rqst_ctx::s_get_rqst_path_cb = NULL;
get_rqst_data_cb_t rqst_ctx::s_get_rqst_query_str_cb = NULL;
get_rqst_data_size_cb_t rqst_ctx::s_get_rqst_header_size_cb = NULL;
get_rqst_data_w_key_cb_t rqst_ctx::s_get_rqst_header_w_key_cb = NULL;
get_rqst_kv_w_idx_cb_t rqst_ctx::s_get_rqst_header_w_idx_cb = NULL;
get_rqst_data_cb_t rqst_ctx::s_get_rqst_id_cb = NULL;
get_rqst_body_data_cb_t rqst_ctx::s_get_rqst_body_str_cb = NULL;
get_rqst_data_cb_t rqst_ctx::s_get_rqst_local_addr_cb = NULL;
get_rqst_data_size_cb_t rqst_ctx::s_get_rqst_canonical_port_cb = NULL;
get_rqst_data_size_cb_t rqst_ctx::s_get_rqst_apparent_cache_status_cb = NULL;
get_rqst_data_size_cb_t rqst_ctx::s_get_rqst_bytes_out_cb = NULL;
get_rqst_data_size_cb_t rqst_ctx::s_get_rqst_bytes_in_cb = NULL;
get_rqst_data_size_cb_t rqst_ctx::s_get_rqst_req_id_cb = NULL;
get_rqst_data_size_cb_t rqst_ctx::s_get_cust_id_cb = NULL;
//: ----------------------------------------------------------------------------
//: static
//: ----------------------------------------------------------------------------
uint32_t rqst_ctx::s_body_arg_len_cap = _DEFAULT_BODY_ARG_LEN_CAP;
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static bool key_in_ignore_list(const pcre_list_t &a_pcre_list,
                               const char *a_data,
                               uint32_t a_data_len)
{
        bool l_match = false;
        for(pcre_list_t::const_iterator i_c = a_pcre_list.begin();
            i_c != a_pcre_list.end();
            ++i_c)
        {
                regex *l_regex = *i_c;
                if(!l_regex)
                {
                        continue;
                }
                int32_t l_s;
                // -----------------------------------------
                // match?
                // -----------------------------------------
                l_s = l_regex->compare(a_data, a_data_len);
                // We have a match
                if(l_s >= 0)
                {
                       l_match = true;
                       return l_match;
                }
        }
        return l_match;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int32_t remove_ignored(arg_list_t &ao_arg_list,
                              const pcre_list_t &a_pcre_list)
{
        // -------------------------------------------------
        // strip ignored cookies
        // -------------------------------------------------
        for(arg_list_t::iterator i_a = ao_arg_list.begin();
            i_a != ao_arg_list.end();)
        {
                bool l_m = false;
                l_m = key_in_ignore_list(a_pcre_list,
                                         i_a->m_key,
                                         i_a->m_key_len);
                if(l_m)
                {
                        ao_arg_list.erase(i_a++);
                        continue;
                }
                ++i_a;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int32_t remove_ignored_const(const_arg_list_t &ao_arg_list,
                                    const pcre_list_t &a_pcre_list)
{
        // -------------------------------------------------
        // strip ignored cookies
        // -------------------------------------------------
        for(const_arg_list_t::iterator i_a = ao_arg_list.begin();
            i_a != ao_arg_list.end();)
        {
                bool l_m = false;
                l_m = key_in_ignore_list(a_pcre_list,
                                         i_a->m_key,
                                         i_a->m_key_len);
                if(l_m)
                {
                        ao_arg_list.erase(i_a++);
                        continue;
                }
                ++i_a;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
rqst_ctx::rqst_ctx(uint32_t a_body_len_max,
                   bool a_parse_json):
        m_src_addr(),
        m_port(0),
        m_scheme(),
        m_protocol(),
        m_line(),
        m_method(),
        m_url(),
        m_uri(),
        m_path(),
        m_base(),
        m_query_str(),
        m_file_ext(),
        m_query_arg_list(),
        m_header_map(),
        m_header_list(),
        m_cookie_list(),
        m_body_len_max(a_body_len_max),
        m_body_data(NULL),
        m_body_len(0),
        m_content_length(0),
        m_parse_json(a_parse_json),
        m_cookie_mutated(),
        m_body_parser(),
        // -------------------------------------------------
        // collections
        // -------------------------------------------------
        m_cx_matched_var(),
        m_cx_matched_var_name(),
        m_cx_rule_map(),
        m_cx_tx_map(),
        // -------------------------------------------------
        // state
        // -------------------------------------------------
        m_intercepted(false),
        m_skip(0),
        m_skip_after(NULL),
        // -------------------------------------------------
        // *************************************************
        // xml optimization
        // *************************************************
        // -------------------------------------------------
        m_xpath_cache_map(NULL)
{
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
rqst_ctx::~rqst_ctx()
{
        // -------------------------------------------------
        // delete query args
        // -------------------------------------------------
        for(arg_list_t::iterator i_q = m_query_arg_list.begin();
            i_q != m_query_arg_list.end();
            ++i_q)
        {
                if(i_q->m_key) { free(i_q->m_key); i_q->m_key = NULL; }
                if(i_q->m_val) { free(i_q->m_val); i_q->m_val = NULL; }
        }
        // -------------------------------------------------
        // delete body args
        // -------------------------------------------------
        for(arg_list_t::iterator i_q = m_body_arg_list.begin();
            i_q != m_body_arg_list.end();
            ++i_q)
        {
                if(i_q->m_key) { free(i_q->m_key); i_q->m_key = NULL; }
                if(i_q->m_val) { free(i_q->m_val); i_q->m_val = NULL; }
        }
        // -------------------------------------------------
        // delete body
        // -------------------------------------------------
        if(m_body_data)
        {
                free(m_body_data);
                m_body_data = NULL;
                m_body_len = 0;
        }
        // -------------------------------------------------
        // *************************************************
        // xml optimization
        // *************************************************
        // -------------------------------------------------
        if(m_xpath_cache_map)
        {
                for(xpath_cache_map_t::iterator i_p = m_xpath_cache_map->begin();
                    i_p != m_xpath_cache_map->end();
                    ++i_p)
                {
                        for(xpath_arg_list_t::iterator i_s = i_p->second.begin();
                            i_s != i_p->second.end();
                            ++i_s)
                        {
                                if(i_s->m_val)
                                {
                                        free((char *)i_s->m_val);
                                        i_s->m_val = NULL;
                                        i_s->m_val_len = 0;
                                }
                        }
                }
                delete m_xpath_cache_map;
        }
        // -------------------------------------------------
        // delete parser
        // -------------------------------------------------
        if(m_body_parser) { delete m_body_parser; m_body_parser = NULL;}
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t rqst_ctx::init_phase_0(void *a_ctx)
{
        // -------------------------------------------------
        // src addr
        // -------------------------------------------------
        if(s_get_rqst_src_addr_cb)
        {
                int32_t l_s;
                // get src address
                l_s = s_get_rqst_src_addr_cb(&m_src_addr.m_data,
                                             m_src_addr.m_len,
                                             a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // hardcode protocol to http/1.1
        // -------------------------------------------------
        m_protocol.m_data = "HTTP/1.1";
        m_protocol.m_len = strlen(m_protocol.m_data);
        // -------------------------------------------------
        // method
        // -------------------------------------------------
        if(s_get_rqst_method_cb)
        {
                int32_t l_s;
                // get method
                l_s = s_get_rqst_method_cb(&m_method.m_data,
                                           m_method.m_len,
                                           a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // uri
        // -------------------------------------------------
        if(s_get_rqst_uri_cb)
        {
                int32_t l_s;
                // get uri
                l_s = s_get_rqst_uri_cb(&m_uri.m_data,
                                        m_uri.m_len,
                                        a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // uri_raw
        // -------------------------------------------------
        if(s_get_rqst_path_cb)
        {
                int32_t l_s;
                // get raw uri
                l_s = s_get_rqst_path_cb(&m_path.m_data,
                                         m_path.m_len,
                                         a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // get base
                // -----------------------------------------
                if(m_path.m_data &&
                   m_path.m_len)
                {
                        const void *l_ptr = NULL;
                        l_ptr = memrchr(m_path.m_data, '/', (int)m_path.m_len);
                        if(l_ptr)
                        {
                                m_base.m_data = ((const char *)(l_ptr) + 1);
                                m_base.m_len = m_path.m_len - ((uint32_t)((const char *)l_ptr - m_path.m_data)) - 1;
                        }
                }
                // -----------------------------------------
                // get file_ext
                // -----------------------------------------
                if(m_base.m_data &&
                   m_base.m_len)
                {
                        const void *l_ptr = NULL;
                        l_ptr = memrchr(m_base.m_data, '.', (int)m_base.m_len);
                        if(l_ptr)
                        {
                                m_file_ext.m_data = ((const char *)(l_ptr));
                                m_file_ext.m_len = m_base.m_len - ((uint32_t)((const char *)l_ptr - m_base.m_data)) - 1;
                        }
                }
        }
        // -------------------------------------------------
        // headers
        // -------------------------------------------------
        uint32_t l_hdr_size = 0;
        if(s_get_rqst_header_size_cb)
        {
                int32_t l_s;
                l_s = s_get_rqst_header_size_cb(l_hdr_size, a_ctx);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_size_cb");
                }
        }
        for(uint32_t i_h = 0; i_h < l_hdr_size; ++i_h)
        {
                const_arg_t l_hdr;
                if(!s_get_rqst_header_w_idx_cb)
                {
                        continue;
                }
                int32_t l_s;
                l_s = s_get_rqst_header_w_idx_cb(&l_hdr.m_key, l_hdr.m_key_len,
                                                 &l_hdr.m_val, l_hdr.m_val_len,
                                                 a_ctx,
                                                 i_h);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_w_idx_cb: idx: %u", i_h);
                        continue;
                }
                if(!l_hdr.m_key)
                {
                        continue;
                }
                m_header_list.push_back(l_hdr);
                // -----------------------------------------
                // parse content-type header...
                // e.g: Content-type:multipart/form-data; application/xml(asdhbc)  ;   aasdhhhasd;asdajj-asdad    ;; ;;"
                // -----------------------------------------
                if(strncasecmp(l_hdr.m_key, "Content-Type", sizeof("Content-Type") - 1) == 0)
                {
                        parse_content_type(m_content_type_list, &l_hdr);
                }
                // -----------------------------------------
                // map
                // -----------------------------------------
                data_t l_key;
                l_key.m_data = l_hdr.m_key;
                l_key.m_len = l_hdr.m_key_len;
                data_t l_val;
                l_val.m_data = l_hdr.m_val;
                l_val.m_len = l_hdr.m_val_len;
                m_header_map[l_key] = l_val;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t rqst_ctx::init_phase_1(void *a_ctx,
                               const pcre_list_t &a_il_query,
                               const pcre_list_t &a_il_header,
                               const pcre_list_t &a_il_cookie)
{
        // -------------------------------------------------
        // src addr
        // -------------------------------------------------
        if(s_get_rqst_src_addr_cb)
        {
                int32_t l_s;
                // get src address
                l_s = s_get_rqst_src_addr_cb(&m_src_addr.m_data,
                                             m_src_addr.m_len,
                                             a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // host
        // -------------------------------------------------
        if(s_get_rqst_host_cb)
        {
                int32_t l_s;
                // get src address
                l_s = s_get_rqst_host_cb(&m_host.m_data,
                                         m_host.m_len,
                                         a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // port
        // -------------------------------------------------
        if(s_get_rqst_port_cb)
        {
                int32_t l_s;
                // get request port
                l_s = s_get_rqst_port_cb(m_port,
                                         a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // scheme (http/https)
        // -------------------------------------------------
        if(s_get_rqst_scheme_cb)
        {
                int32_t l_s;
                // get request scheme
                l_s = s_get_rqst_scheme_cb(&m_scheme.m_data,
                                           m_scheme.m_len,
                                           a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
#if 0
        // -------------------------------------------------
        // protocol
        // -------------------------------------------------
        if(s_get_rqst_protocol_cb)
        {
                int32_t l_s;
                // get rqst protocol
                l_s = s_get_rqst_protocol_cb(&m_protocol.m_data,
                                              m_protocol.m_len,
                                              a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
#endif
        // -------------------------------------------------
        // hardcode protocol to http/1.1
        // -------------------------------------------------
        m_protocol.m_data = "HTTP/1.1";
        m_protocol.m_len = strlen(m_protocol.m_data);
        // -------------------------------------------------
        // line
        // -------------------------------------------------
        if(s_get_rqst_line_cb)
        {
                int32_t l_s;
                // get request line
                l_s = s_get_rqst_line_cb(&m_line.m_data,
                                         m_line.m_len,
                                         a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // method
        // -------------------------------------------------
        if(s_get_rqst_method_cb)
        {
                int32_t l_s;
                // get method
                l_s = s_get_rqst_method_cb(&m_method.m_data,
                                           m_method.m_len,
                                           a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // url
        // -------------------------------------------------
        if(s_get_rqst_url_cb)
        {
                int32_t l_s;
                // get uri
                l_s = s_get_rqst_url_cb(&m_url.m_data,
                                        m_url.m_len,
                                        a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // uri
        // -------------------------------------------------
        if(s_get_rqst_uri_cb)
        {
                int32_t l_s;
                // get uri
                l_s = s_get_rqst_uri_cb(&m_uri.m_data,
                                        m_uri.m_len,
                                        a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // uri_raw
        // -------------------------------------------------
        if(s_get_rqst_path_cb)
        {
                int32_t l_s;
                // get raw uri
                l_s = s_get_rqst_path_cb(&m_path.m_data,
                                         m_path.m_len,
                                         a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // get base
                // -----------------------------------------
                if(m_path.m_data &&
                   m_path.m_len)
                {
                        const void *l_ptr = NULL;
                        l_ptr = memrchr(m_path.m_data, '/', (int)m_path.m_len);
                        if(l_ptr)
                        {
                                m_base.m_data = ((const char *)(l_ptr) + 1);
                                m_base.m_len = m_path.m_len - ((uint32_t)((const char *)l_ptr - m_path.m_data)) - 1;
                        }
                }
        }
        // -------------------------------------------------
        // query string...
        // -------------------------------------------------
        if(s_get_rqst_query_str_cb)
        {
                int32_t l_s;
                // get q string
                l_s = s_get_rqst_query_str_cb(&m_query_str.m_data,
                                              m_query_str.m_len,
                                              a_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // parse args
                uint32_t l_invalid_cnt = 0;
                l_s = parse_args(m_query_arg_list,
                                 l_invalid_cnt,
                                 m_query_str.m_data,
                                 m_query_str.m_len,
                                 '&');
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // remove ignored
                // -----------------------------------------
                l_s = remove_ignored(m_query_arg_list, a_il_query);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // headers
        // -------------------------------------------------
        uint32_t l_hdr_size = 0;
        if(s_get_rqst_header_size_cb)
        {
                int32_t l_s;
                l_s = s_get_rqst_header_size_cb(l_hdr_size, a_ctx);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_size_cb");
                }
        }
        for(uint32_t i_h = 0; i_h < l_hdr_size; ++i_h)
        {
                const_arg_t l_hdr;
                if(!s_get_rqst_header_w_idx_cb)
                {
                        continue;
                }
                int32_t l_s;
                l_s = s_get_rqst_header_w_idx_cb(&l_hdr.m_key, l_hdr.m_key_len,
                                                 &l_hdr.m_val, l_hdr.m_val_len,
                                                 a_ctx,
                                                 i_h);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_w_idx_cb: idx: %u", i_h);
                        continue;
                }
                if(!l_hdr.m_key)
                {
                        continue;
                }
                // -----------------------------------------
                // parse cookie header...
                // -----------------------------------------
                if(strncasecmp(l_hdr.m_key, "Cookie", sizeof("Cookie")) == 0)
                {
                        int32_t l_s;
                        // ---------------------------------
                        // parse...
                        // ---------------------------------
                        l_s = parse_cookies(m_cookie_list,
                                            l_hdr.m_val,
                                            l_hdr.m_val_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO -log error???
                                continue;
                        }
                        // ---------------------------------
                        // remove ignored
                        // ---------------------------------
                        l_s = remove_ignored_const(m_cookie_list, a_il_cookie);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO log reason???
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // regenerate mutated cookie
                        // ---------------------------------
                        m_cookie_mutated.clear();
                        uint32_t i_c_idx = 0;
                        uint32_t l_c_len = m_cookie_list.size();
                        for(const_arg_list_t::const_iterator i_c = m_cookie_list.begin();
                            i_c != m_cookie_list.end();
                            ++i_c, ++i_c_idx)
                        {
                                m_cookie_mutated.append(i_c->m_key, i_c->m_key_len);
                                m_cookie_mutated += "=";
                                m_cookie_mutated.append(i_c->m_val, i_c->m_val_len);
                                if(i_c_idx < (l_c_len - 1))
                                {
                                        m_cookie_mutated += ";";
                                }
                        }
                        const_arg_t l_arg;
                        l_arg.m_key = "Cookie";
                        l_arg.m_key_len = sizeof("Cookie") - 1;
                        l_arg.m_val = m_cookie_mutated.c_str();
                        l_arg.m_val_len = m_cookie_mutated.length();
                        m_header_list.push_back(l_arg);
                        // ---------------------------------
                        // map
                        // ---------------------------------
                        data_t l_key;
                        l_key.m_data = l_arg.m_key;
                        l_key.m_len = l_arg.m_key_len;
                        data_t l_val;
                        l_val.m_data = l_arg.m_val;
                        l_val.m_len = l_arg.m_val_len;
                        m_header_map[l_key] = l_val;
                }
                // -----------------------------------------
                // else just add header...
                // -----------------------------------------
                else
                {
                        m_header_list.push_back(l_hdr);
                        // ---------------------------------
                        // map
                        // ---------------------------------
                        data_t l_key;
                        l_key.m_data = l_hdr.m_key;
                        l_key.m_len = l_hdr.m_key_len;
                        data_t l_val;
                        l_val.m_data = l_hdr.m_val;
                        l_val.m_len = l_hdr.m_val_len;
                        m_header_map[l_key] = l_val;
                }
                // -----------------------------------------
                // parse content-type header...
                // e.g: Content-type:multipart/form-data; application/xml(asdhbc)  ;   aasdhhhasd;asdajj-asdad    ;; ;;"
                // -----------------------------------------
                if(strncasecmp(l_hdr.m_key, "Content-Type", sizeof("Content-Type") - 1) == 0)
                {
                        parse_content_type(m_content_type_list, &l_hdr);
                }
                // Get content-length, to be verified in phase 2
                if(strncasecmp(l_hdr.m_key, "Content-Length", sizeof("Content-Length") - 1) == 0)
                {
                        m_content_length = strntoul(l_hdr.m_val , l_hdr.m_val_len, NULL, 10);
                }
        }
        // -------------------------------------------------
        // remove ignored
        // -------------------------------------------------
        int32_t l_s;
        l_s = remove_ignored_const(m_header_list, a_il_header);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t rqst_ctx::init_phase_2(const ctype_parser_map_t &a_ctype_parser_map,
                               void *a_ctx)
{
        // -------------------------------------------------
        // request body data
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get content length
        // -------------------------------------------------
        if(m_content_length == ULONG_MAX)
        {
                // TODO -return reason...
                return WAFLZ_STATUS_OK;
        }
        if(m_content_length <= 0)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // calculate body size
        // -------------------------------------------------
        uint32_t l_body_len;
        l_body_len = m_content_length > m_body_len_max ? m_body_len_max : m_content_length;
        //NDBG_PRINT("body len %d\n", l_body_len);
        // -------------------------------------------------
        // TODO -413 on > max???
        // -------------------------------------------------
        // TODO -should respond here and 413 the request???
        // -------------------------------------------------
        // get content type
        // -------------------------------------------------
        if(!m_content_type_list.size())
        {
                return WAFLZ_STATUS_OK;
        }
        if(!m_content_type_list.size())
        {
                return WAFLZ_STATUS_OK;
        }
        // Get the first one from list
        // TODO: may be check through the list?
        data_t l_type = m_content_type_list.front();
        std::string l_ct;
        l_ct.assign(l_type.m_data, l_type.m_len);
        ctype_parser_map_t::const_iterator i_p = a_ctype_parser_map.find(l_ct);
        if(i_p == a_ctype_parser_map.end())
        {
                return WAFLZ_STATUS_OK;
        }
        if(m_body_parser)
        {
                delete m_body_parser;
                m_body_parser = NULL;
        }
        // -------------------------------------------------
        // init parser...
        // -------------------------------------------------
        switch(i_p->second)
        {
        // -------------------------------------------------
        // PARSER_NONE
        // -------------------------------------------------
        case PARSER_NONE:
        {
                // do nothing...
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // PARSER_URL_ENCODED
        // -------------------------------------------------
        case PARSER_URL_ENCODED:
        {
                m_body_parser = new parser_url_encoded(this);
                break;
        }
        // -------------------------------------------------
        // PARSER_XML
        // -------------------------------------------------
        case PARSER_XML:
        {
                m_body_parser = new parser_xml(this);
                break;
        }
        // -------------------------------------------------
        // PARSER_JSON
        // -------------------------------------------------
        case PARSER_JSON:
        {
                if(!m_parse_json)
                {
                        // do nothing...
                        return WAFLZ_STATUS_OK;
                }
                m_body_parser = new parser_json(this);
                break;
        }
        // -------------------------------------------------
        // PARSER_MULTIPART
        // -------------------------------------------------
        case PARSER_MULTIPART:
        {
                // TODO -fix???
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                // do nothing...
                return WAFLZ_STATUS_OK;
        }
        }
        if(!m_body_parser)
        {
                // do nothing...
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // init parser
        // -------------------------------------------------
        l_s = m_body_parser->init();
        if(l_s != WAFLZ_STATUS_OK)
        {
                // do nothing...
                //NDBG_PRINT("error m_body_parser->init()\n");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // TODO get request body
        // -------------------------------------------------
        if(!s_get_rqst_body_str_cb)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // allocate max body size
        // -------------------------------------------------
        if(m_body_data)
        {
                free(m_body_data);
                m_body_data = NULL;
                m_body_len = 0;
        }
        m_body_data = (char *)malloc(sizeof(char)*l_body_len);
        bool l_is_eos = false;
        uint32_t l_rd_count = 0;
        uint32_t l_rd_count_total = 0;
        // -------------------------------------------------
        // while body data...
        // -------------------------------------------------
        while(!l_is_eos &&
              (l_rd_count_total < l_body_len))
        {
                l_rd_count = 0;
                char *l_buf = m_body_data+l_rd_count_total;
                uint64_t l_to_read = l_body_len-l_rd_count_total;
                l_s = s_get_rqst_body_str_cb(l_buf,
                                             l_rd_count,
                                             l_is_eos,
                                             a_ctx,
                                             l_to_read);
                if(l_s != 0)
                {
                        return WAFLZ_STATUS_OK;
                }
                if(!l_rd_count)
                {
                        continue;
                }
                // -----------------------------------------
                // process chunk
                // -----------------------------------------
                l_s = m_body_parser->process_chunk(l_buf, l_rd_count);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        //NDBG_PRINT("error m_body_parser->process_chunk()\n");
                        return WAFLZ_STATUS_ERROR;
                }
                l_rd_count_total += l_rd_count;
                //NDBG_PRINT("read: %6d / %6d\n", (int)l_rd_count, l_rd_count_total);
        }
        m_body_len = l_rd_count_total;
        // -------------------------------------------------
        // finish
        // -------------------------------------------------
        l_s = m_body_parser->finish();
        if(l_s != WAFLZ_STATUS_OK)
        {
                // Set request body error var in tx map and return
                m_cx_tx_map["REQBODY_ERROR"] = "1";
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // cap the arg list size
        // -------------------------------------------------
        for(arg_list_t::iterator i_k = m_body_arg_list.begin();
            i_k != m_body_arg_list.end();
            ++i_k)
        {
                if(i_k->m_key_len > s_body_arg_len_cap)
                {
                        i_k->m_key_len = s_body_arg_len_cap;
                }
                if(i_k->m_val_len > s_body_arg_len_cap)
                {
                        i_k->m_val_len = s_body_arg_len_cap;
                }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void rqst_ctx::show(void)
{
        NDBG_OUTPUT("+------------------------------------------------+\n");
        NDBG_OUTPUT("|            %sR E Q U E S T   C T X%s               |\n", ANSI_COLOR_FG_WHITE, ANSI_COLOR_OFF);
        NDBG_OUTPUT("+------------------------------------------------+-----------------------------+\n");
        NDBG_OUTPUT(": %sSRC_ADDR%s:     %.*s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_src_addr.m_len, m_src_addr.m_data);
        NDBG_OUTPUT(": %sPORT%s:         %d\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, (int)m_port);
        NDBG_OUTPUT(": %sSCHEME%s:       %.*s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_scheme.m_len, m_scheme.m_data);
        NDBG_OUTPUT(": %sPROTOCOL%s:     %.*s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_protocol.m_len, m_protocol.m_data);
        NDBG_OUTPUT(": %sLINE%s:         %.*s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_line.m_len, m_line.m_data);
        NDBG_OUTPUT(": %sURI%s:          %.*s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_uri.m_len, m_uri.m_data);
        NDBG_OUTPUT(": %sMETHOD%s:       %.*s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_method.m_len, m_method.m_data);
        NDBG_OUTPUT(": %sQUERY_STR%s:    %.*s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_query_str.m_len, m_query_str.m_data);
        NDBG_OUTPUT(": ------------+ \n");
        NDBG_OUTPUT(": %sQUERY_ARGS%s  :  \n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
        NDBG_OUTPUT(": ------------+--------------------------------------------+ \n");
        for(arg_list_t::const_iterator i_q = m_query_arg_list.begin();
            i_q != m_query_arg_list.end();
            ++i_q)
        {
                NDBG_OUTPUT(": %s%.*s%s: %.*s\n",
                            ANSI_COLOR_FG_YELLOW, i_q->m_key_len, i_q->m_key, ANSI_COLOR_OFF,
                            i_q->m_val_len, i_q->m_val);
        }
        NDBG_OUTPUT(": ------------+ \n");
        NDBG_OUTPUT(": %sHEADER_LIST%s : \n", ANSI_COLOR_FG_CYAN, ANSI_COLOR_OFF);
        NDBG_OUTPUT(": ------------+--------------------------------------------+ \n");
        for(const_arg_list_t::const_iterator i_q = m_header_list.begin();
            i_q != m_header_list.end();
            ++i_q)
        {
                NDBG_OUTPUT(": %s%.*s%s: %.*s\n",
                            ANSI_COLOR_FG_YELLOW, i_q->m_key_len, i_q->m_key, ANSI_COLOR_OFF,
                            i_q->m_val_len, i_q->m_val);
        }
        NDBG_OUTPUT(": ------------+ \n");
        NDBG_OUTPUT(": %sCOOKIE_LIST%s : \n", ANSI_COLOR_FG_MAGENTA, ANSI_COLOR_OFF);
        NDBG_OUTPUT(": ------------+--------------------------------------------+ \n");
        for(const_arg_list_t::const_iterator i_q = m_cookie_list.begin();
            i_q != m_cookie_list.end();
            ++i_q)
        {
                NDBG_OUTPUT(": %s%.*s%s: %.*s\n",
                            ANSI_COLOR_FG_YELLOW, i_q->m_key_len, i_q->m_key, ANSI_COLOR_OFF,
                            i_q->m_val_len, i_q->m_val);
        }
        NDBG_OUTPUT("+------------------------------------------------------------------------------+\n");
}
}

