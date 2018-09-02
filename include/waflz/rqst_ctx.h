//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    rqst_ctx.h
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
#ifndef _RQST_CTX_H
#define _RQST_CTX_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <waflz/def.h>
#include <waflz/arg.h>
#include <waflz/parser.h>
#include <waflz/waf.h>
#include <list>
#include <map>
#include <strings.h>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
class waf;
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
struct cx_case_i_comp
{
        bool operator() (const std::string& lhs, const std::string& rhs) const
        {
                return strcasecmp(lhs.c_str(), rhs.c_str()) < 0;
        }
};
typedef std::map<std::string, std::string, cx_case_i_comp> cx_map_t;
typedef std::map <std::string, uint32_t> count_map_t;
typedef std::map <data_t, data_t, data_case_i_comp> data_map_t;
typedef std::list<data_t> data_list_t;
// ---------------------------------------------------------
// *********************************************************
// xml optimization
// *********************************************************
// ---------------------------------------------------------
typedef std::list <const_arg_t> xpath_arg_list_t;
typedef std::map <std::string, xpath_arg_list_t> xpath_cache_map_t;
//: ----------------------------------------------------------------------------
//: rqst_ctx
//: ----------------------------------------------------------------------------
class rqst_ctx
{
public:
        // -------------------------------------------------
        // callbacks
        // -------------------------------------------------
        static get_rqst_data_cb_t s_get_rqst_src_addr_cb;
        static get_rqst_data_cb_t s_get_rqst_host_cb;
        static get_rqst_data_size_cb_t s_get_rqst_port_cb;
        static get_rqst_data_cb_t s_get_rqst_scheme_cb;
        static get_rqst_data_cb_t s_get_rqst_protocol_cb;
        static get_rqst_data_cb_t s_get_rqst_line_cb;
        static get_rqst_data_cb_t s_get_rqst_method_cb;
        static get_rqst_data_cb_t s_get_rqst_url_cb;
        static get_rqst_data_cb_t s_get_rqst_uri_cb;
        static get_rqst_data_cb_t s_get_rqst_path_cb;
        static get_rqst_data_cb_t s_get_rqst_query_str_cb;
        static get_rqst_data_size_cb_t s_get_rqst_header_size_cb;
        static get_rqst_data_w_key_cb_t s_get_rqst_header_w_key_cb;
        static get_rqst_kv_w_idx_cb_t s_get_rqst_header_w_idx_cb;
        static get_rqst_data_cb_t s_get_rqst_id_cb;
        static get_rqst_body_data_cb_t s_get_rqst_body_str_cb;
        static get_rqst_data_cb_t s_get_rqst_local_addr_cb;
        static get_rqst_data_size_cb_t s_get_rqst_canonical_port_cb;
        static get_rqst_data_size_cb_t s_get_rqst_apparent_cache_status_cb;
        static get_rqst_data_size_cb_t s_get_rqst_bytes_out_cb;
        static get_rqst_data_size_cb_t s_get_rqst_bytes_in_cb;
        static get_rqst_data_size_cb_t s_get_rqst_req_id_cb;
        static get_rqst_data_size_cb_t s_get_cust_id_cb;
        // -------------------------------------------------
        // static members
        // -------------------------------------------------
        static uint32_t s_body_arg_len_cap;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        rqst_ctx(uint32_t a_body_len_max,
                 bool a_parse_json = false);
        ~rqst_ctx();
        int32_t init_phase_0(void *a_ctx);
        int32_t init_phase_1(void *a_ctx,
                             const pcre_list_t &a_il_query,
                             const pcre_list_t &a_il_header,
                             const pcre_list_t &a_il_cookie);
        int32_t init_phase_2(const ctype_parser_map_t &a_ctype_parser_map, void *a_ctx);
        void show(void);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        data_t m_src_addr;
        data_t m_host;
        uint32_t m_port;
        data_t m_scheme;
        data_t m_protocol;
        data_t m_line;
        data_t m_method;
        data_t m_url;
        data_t m_uri;
        data_t m_path;
        data_t m_base;
        data_t m_query_str;
        data_t m_file_ext;
        arg_list_t m_query_arg_list;
        arg_list_t m_body_arg_list;
        data_map_t m_header_map;
        const_arg_list_t m_header_list;
        const_arg_list_t m_cookie_list;
        data_list_t m_content_type_list;
        const uint32_t m_body_len_max;
        char *m_body_data;
        uint32_t m_body_len;
        uint32_t m_content_length;
        bool m_parse_json;
        std::string m_cookie_mutated;
        // -------------------------------------------------
        // body parser
        // -------------------------------------------------
        parser *m_body_parser;
        // -------------------------------------------------
        // collections...
        // -------------------------------------------------
        std::string m_cx_matched_var;
        std::string m_cx_matched_var_name;
        data_map_t m_cx_rule_map;
        cx_map_t m_cx_tx_map;
        // -------------------------------------------------
        // state
        // -------------------------------------------------
        bool m_intercepted;
        uint32_t m_skip;
        const char * m_skip_after;
        // -------------------------------------------------
        // *************************************************
        // xml optimization
        // *************************************************
        // -------------------------------------------------
        xpath_cache_map_t *m_xpath_cache_map;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        rqst_ctx(const rqst_ctx &);
        rqst_ctx& operator=(const rqst_ctx &);
};
}
#endif
