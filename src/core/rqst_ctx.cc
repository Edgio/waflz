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
#include "event.pb.h"
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "waflz/geoip2_mmdb.h"
#include "waflz/string_util.h"
#include "core/decode.h"
#include "op/regex.h"
#include "support/ndebug.h"
#include "support/time_util.h"
#include "parser/parser_url_encoded.h"
#include "parser/parser_xml.h"
#include "parser/parser_json.h"
#include <stdlib.h>
#include <string.h>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define _DEFAULT_BODY_ARG_LEN_CAP 4096
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define GET_RQST_DATA(_cb) do { \
        l_buf = NULL; \
        l_buf_len = 0; \
        if(_cb) { \
                l_s = _cb(&l_buf, &l_buf_len, m_ctx); \
                if(l_s != 0) { \
                        return WAFLZ_STATUS_ERROR; \
                } \
        } \
} while(0)
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: static
//: ----------------------------------------------------------------------------
uint32_t rqst_ctx::s_body_arg_len_cap = _DEFAULT_BODY_ARG_LEN_CAP;
get_data_cb_t rqst_ctx::s_get_bot_ch_prob = NULL;
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
//: \details Check whether the text in the buf begins with JSON structure
//: \return  true: on finding json structure in the begining
//:          false: on not finding json structure in the begining
//: \param   a_buf: Input buffer
//:          a_len: length of buffer
//: ----------------------------------------------------------------------------
static bool infer_is_json(const char *a_buf, uint32_t a_len)
{
        // -------------------------------------------------
        // shortest json string is []
        // -------------------------------------------------
        if(!a_buf ||
           a_len <=2)
        {
                return false;
        }
        // -------------------------------------------------
        // We will only inspect first 16 characters
        // -------------------------------------------------
        uint32_t l_max_check = (a_len < 16) ? a_len : 16;
        uint32_t i_i = 0;
        while (i_i < l_max_check)
        {
                // -----------------------------------------
                // skip all whitespace and newline before we
                // look ahead for json structure
                // -----------------------------------------
                if(isspace(a_buf[i_i]))
                {
                        ++i_i;
                }
                else
                {
                        if((a_buf[i_i] == '{'))
                        {
                                // -------------------------
                                // check for next char
                                // -------------------------
                                ++i_i;
                                if((isspace(a_buf[i_i])) ||
                                   (a_buf[i_i] == '"'))
                                   {
                                        return true;
                                   }
                        }
                        else if((a_buf[i_i] == '['))
                        {
                                // -------------------------
                                // check for next char
                                // ", {, true, false, null
                                // numbers 0-9
                                // -------------------------
                                ++i_i;
                                if((isspace(a_buf[i_i])) ||
                                   (a_buf[i_i] == '"')   ||
                                   (a_buf[i_i] == '{')   ||
                                   (a_buf[i_i] == '[')   ||
                                   (a_buf[i_i] == 't')   ||
                                   (a_buf[i_i] == 'f')   ||
                                   (a_buf[i_i] == 'n')   ||
                                   (uint32_t(a_buf[i_i]) >= 48 && uint32_t(a_buf[i_i]) <= 57))
                                   {
                                        return true;
                                   }
                        }
                        return false;
                }
        }
        return false;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
rqst_ctx::rqst_ctx(void *a_ctx,
                   uint32_t a_body_len_max,
                   const rqst_ctx_callbacks *a_callbacks,
                   bool a_parse_xml,
                   bool a_parse_json):
        m_src_addr(),
        m_local_addr(),
        m_host(),
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
        m_body_arg_list(),
        m_header_map(),
        m_header_list(),
        m_cookie_list(),
        m_cookie_map(),
        m_apparent_cache_status(),
        m_content_type_list(),
        m_uri_path_len(0),
        m_body_len_max(a_body_len_max),
        m_body_data(NULL),
        m_body_len(0),
        m_content_length(0),
        m_parse_xml(a_parse_xml),
        m_parse_json(a_parse_json),
        m_cookie_mutated(),
        m_req_uuid(),
        m_bytes_out(0),
        m_bytes_in(0),
        m_token(),
        m_resp_status(0),
        m_signal_enf(0),
        m_waf_analyzed(false),
        m_limit_analyzed(false),
        m_limit(NULL),
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
        m_init_phase_1(false),
        m_init_phase_2(false),
        m_intercepted(false),
        m_wl(false),
        m_wl_audit(false),
        m_wl_prod(false),
        m_skip(0),
        m_skip_after(NULL),
        m_event(NULL),
        // -------------------------------------------------
        // *************************************************
        // xml optimization
        // *************************************************
        // -------------------------------------------------
        m_xpath_cache_map(NULL),
        m_callbacks(a_callbacks),
        // -------------------------------------------------
        // *************************************************
        // extensions
        // *************************************************
        // -------------------------------------------------
        m_src_asn(0),
        m_src_asn_str(),
        m_geo_cn2(),
        m_xml_capture_xxe(true),
        m_bot_ch(),
        m_ans(0),
        m_ctx(a_ctx)
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
        // -------------------------------------------------
        // delete any tokens
        // -------------------------------------------------
        if(m_token.m_data) { free(m_token.m_data); m_token.m_data = NULL; m_token.m_len = 0; }
        // -------------------------------------------------
        // delete any extensions
        // -------------------------------------------------
        if(m_src_asn_str.m_data) { free(m_src_asn_str.m_data); m_src_asn_str.m_data = NULL; m_src_asn_str.m_len = 0; }
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t rqst_ctx::reset_phase_1()
{
        // -------------------------------------------------
        // delete query args
        // -------------------------------------------------
        if(!m_query_arg_list.empty())
        {
                for(arg_list_t::iterator i_q = m_query_arg_list.begin();
                    i_q != m_query_arg_list.end();
                    ++i_q)
                {
                        if(i_q->m_key) { free(i_q->m_key); i_q->m_key = NULL; }
                        if(i_q->m_val) { free(i_q->m_val); i_q->m_val = NULL; }
                }
                m_query_arg_list.clear();
        }
        // -------------------------------------------------
        // clear cookies
        // -------------------------------------------------
        m_cookie_list.clear();
        // -------------------------------------------------
        // clear headers
        // -------------------------------------------------
        m_header_list.clear();
        // -------------------------------------------------
        // clear tx map
        // -------------------------------------------------
        m_cx_tx_map.clear();
        // -------------------------------------------------
        // clear header map
        // -------------------------------------------------
        m_header_map.clear();
        // -------------------------------------------------
        // clear rule map
        // -------------------------------------------------
        m_cx_rule_map.clear();
        // -------------------------------------------------
        // clear vars
        // -------------------------------------------------
        m_cx_matched_var.clear();
        m_cx_matched_var_name.clear();
        m_cookie_mutated.clear();
        m_init_phase_1 = false;
        m_intercepted = false;
        m_wl = false;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t rqst_ctx::init_phase_1(geoip2_mmdb &a_geoip2_mmdb,
                               const pcre_list_t *a_il_query,
                               const pcre_list_t *a_il_header,
                               const pcre_list_t *a_il_cookie)
{
        if(m_init_phase_1)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // src addr
        // -------------------------------------------------
        if(m_callbacks && m_callbacks->m_get_rqst_src_addr_cb)
        {
                int32_t l_s;
                // get src address
                l_s = m_callbacks->m_get_rqst_src_addr_cb(&m_src_addr.m_data,
                                             &m_src_addr.m_len,
                                             m_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // country code
        // -------------------------------------------------
        if(m_src_addr.m_data &&
           m_src_addr.m_len)
        {
                int32_t l_s;
                m_geo_cn2.m_data = NULL;
                m_geo_cn2.m_len = 0;
                l_s = a_geoip2_mmdb.get_country(&m_geo_cn2.m_data,
                                                m_geo_cn2.m_len,
                                                m_src_addr.m_data,
                                                m_src_addr.m_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        //NDBG_PRINT("geoip2 country lookup: reason: %s\n",
                        //            a_geoip2_mmdb.get_err_msg());
                        // TODO log reason???
                        // fail is fine...
                }
        }
        // -------------------------------------------------
        // asn
        // -------------------------------------------------
        if(m_src_addr.m_data &&
           m_src_addr.m_len)
        {
                int32_t l_s;
                m_src_asn = 0;
                l_s = a_geoip2_mmdb.get_asn(m_src_asn,
                                            m_src_addr.m_data,
                                            m_src_addr.m_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        //NDBG_PRINT("geoip2 country lookup: reason: %s\n",
                        //           a_geoip2_mmdb.get_err_msg());
                        // TODO log reason???
                        // fail is fine...
                }
                // -----------------------------------------
                // converting to str temporarily for str
                // comparisons...
                // -----------------------------------------
                if(m_src_asn)
                {
                        m_src_asn_str.m_len = asprintf(&(m_src_asn_str.m_data), "%d", m_src_asn);
                }
        }
        // -------------------------------------------------
        // local addr
        // -------------------------------------------------
        if(m_callbacks && m_callbacks->m_get_rqst_local_addr_cb)
        {
                int32_t l_s;
                // get src address
                l_s = m_callbacks->m_get_rqst_local_addr_cb(&m_local_addr.m_data,
                                               &m_local_addr.m_len,
                                               m_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // host
        // -------------------------------------------------
        if(m_callbacks && m_callbacks->m_get_rqst_host_cb)
        {
                int32_t l_s;
                // get src address
                l_s = m_callbacks->m_get_rqst_host_cb(&m_host.m_data,
                                         &m_host.m_len,
                                         m_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // port
        // -------------------------------------------------
        if(m_callbacks && m_callbacks->m_get_rqst_port_cb)
        {
                int32_t l_s;
                // get request port
                l_s = m_callbacks->m_get_rqst_port_cb(&m_port,
                                         m_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // scheme (http/https)
        // -------------------------------------------------
        if(m_callbacks && m_callbacks->m_get_rqst_scheme_cb)
        {
                int32_t l_s;
                // get request scheme
                l_s = m_callbacks->m_get_rqst_scheme_cb(&m_scheme.m_data,
                                           &m_scheme.m_len,
                                           m_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // request uuid
        // -------------------------------------------------
        if(m_callbacks && m_callbacks->m_get_rqst_uuid_cb)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_rqst_uuid_cb(&m_req_uuid.m_data,
                                                      &m_req_uuid.m_len,
                                                      m_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        //return STATUS_ERROR;
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
                                              m_ctx);
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
        if(m_callbacks && m_callbacks->m_get_rqst_line_cb)
        {
                int32_t l_s;
                // get request line
                l_s = m_callbacks->m_get_rqst_line_cb(&m_line.m_data,
                                         &m_line.m_len,
                                         m_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // method
        // -------------------------------------------------
        if(m_callbacks && m_callbacks->m_get_rqst_method_cb)
        {
                int32_t l_s;
                // get method
                l_s = m_callbacks->m_get_rqst_method_cb(&m_method.m_data,
                                           &m_method.m_len,
                                           m_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // get uri, url and quert string
        // According to modsecurity:
        // (REQUEST_URI) : This variable holds the full request URL including the query string data
        // (e.g., /index.php?p=X). However, it will never contain a domain name, even if it was provided on the request line.
        // (REQUEST_URI_RAW): This will contain the domain name
        // if it was provided on the request line (e.g., http://www.example.com/index.php?p=X
        // The domain name depends on request line. Most common form is origin-form
        // according to https://tools.ietf.org/html/rfc7230#section-5.3.1
        // We only support origin form at this moment, which means uri=uri in this case
        // -------------------------------------------------
        if(m_callbacks && m_callbacks->m_get_rqst_uri_cb)
        {
                int32_t l_s;
                // get uri
                l_s = m_callbacks->m_get_rqst_uri_cb(&m_uri.m_data,
                                        &m_uri.m_len,
                                        m_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // get path length w/o q string
                // -----------------------------------------
                m_uri_path_len = m_uri.m_len;
                const char *l_q = NULL;
                l_q = (const char *)memchr(m_uri.m_data, '?', m_uri.m_len);
                if(l_q)
                {
                        m_uri_path_len = l_q - m_uri.m_data;
                        // -----------------------------------------
                        // get query string
                        // -----------------------------------------
                        m_query_str.m_data = l_q + 1;
                        m_query_str.m_len = m_uri.m_len - m_uri_path_len - 1;
                }
                // -----------------------------------------
                // get path
                // -----------------------------------------
                m_path.m_data = m_uri.m_data;
                m_path.m_len = m_uri_path_len;
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
                                m_file_ext.m_len = m_base.m_len - ((uint32_t)((const char *)l_ptr - m_base.m_data));
                        }
                }
                // parse query args
                if(m_query_str.m_data &&
                   m_query_str.m_len)
                {
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
                        if(a_il_query)
                        {
                                l_s = remove_ignored(m_query_arg_list, *a_il_query);
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        // TODO log reason???
                                        return WAFLZ_STATUS_ERROR;
                                }
                        }
                }
        }
        // -------------------------------------------------
        // Url
        // -------------------------------------------------
        if(m_callbacks && m_callbacks->m_get_rqst_url_cb)
        {
                int32_t l_s;
                // get uri
                l_s = m_callbacks->m_get_rqst_url_cb(&m_url.m_data,
                                        &m_url.m_len,
                                        m_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // headers
        // -------------------------------------------------
        uint32_t l_hdr_size = 0;
        if(m_callbacks && m_callbacks->m_get_rqst_header_size_cb)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_rqst_header_size_cb(&l_hdr_size, m_ctx);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_size_cb");
                }
        }
        for(uint32_t i_h = 0; i_h < l_hdr_size; ++i_h)
        {
                const_arg_t l_hdr;
                if(!m_callbacks || !m_callbacks->m_get_rqst_header_w_idx_cb)
                {
                        continue;
                }
                int32_t l_s;
                l_s = m_callbacks->m_get_rqst_header_w_idx_cb(&l_hdr.m_key, &l_hdr.m_key_len,
                                                 &l_hdr.m_val, &l_hdr.m_val_len,
                                                 m_ctx,
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
                        if(a_il_cookie)
                        {
                                l_s = remove_ignored_const(m_cookie_list, *a_il_cookie);
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        // TODO log reason???
                                        return WAFLZ_STATUS_ERROR;
                                }
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
                                // -------------------------
                                // add to map
                                // -------------------------
                                data_t l_key;
                                l_key.m_data = i_c->m_key;
                                l_key.m_len = i_c->m_key_len;
                                data_t l_val;
                                l_val.m_data = i_c->m_val;
                                l_val.m_len = i_c->m_val_len;
                                m_cookie_map[l_key] = l_val;

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
        if(a_il_header)
        {
                int32_t l_s;
                l_s = remove_ignored_const(m_header_list, *a_il_header);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // APPARENT_CACHE_STATUS
        // TODO: check again
        // -------------------------------------------------
        if(m_callbacks && m_callbacks->m_get_rqst_apparent_cache_status_cb)
        {
                int32_t l_s;
                uint32_t l_v;
                l_s = m_callbacks->m_get_rqst_apparent_cache_status_cb(&l_v,
                                                                       m_ctx);
                if(l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
                m_apparent_cache_status = l_v;
        }
        m_init_phase_1 = true;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t rqst_ctx::init_phase_2(const ctype_parser_map_t &a_ctype_parser_map)
{
        if(m_init_phase_2)
        {
                return WAFLZ_STATUS_OK;
        }
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
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        if(m_content_length <= 0)
        {
                m_init_phase_2 = true;
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
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        if(!m_content_type_list.size())
        {
                m_init_phase_2 = true;
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
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        if(m_body_parser)
        {
                delete m_body_parser;
                m_body_parser = NULL;
        }
        bool l_is_url_encoded = false;
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
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // PARSER_URL_ENCODED
        // -------------------------------------------------
        case PARSER_URL_ENCODED:
        {
                m_body_parser = new parser_url_encoded(this);
                l_is_url_encoded = true;
                break;
        }
        // -------------------------------------------------
        // PARSER_XML
        // -------------------------------------------------
        case PARSER_XML:
        {
                if(!m_parse_xml)
                {
                        // do nothing...
                        m_init_phase_2 = true;
                        return WAFLZ_STATUS_OK;
                }
                parser_xml* l_parser_xml = new parser_xml(this);
                // -----------------------------------------
                // optional set capture xxe
                // -----------------------------------------
                l_parser_xml->set_capture_xxe(m_xml_capture_xxe);
                m_body_parser = l_parser_xml;
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
                        m_init_phase_2 = true;
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
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                // do nothing...
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        }
        if(!m_body_parser)
        {
                // do nothing...
                m_init_phase_2 = true;
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
        if(!m_callbacks->m_get_rqst_body_str_cb)
        {
                m_init_phase_2 = true;
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
                uint32_t l_to_read = l_body_len-l_rd_count_total;
                l_s = m_callbacks->m_get_rqst_body_str_cb(l_buf,
                                             &l_rd_count,
                                             &l_is_eos,
                                             m_ctx,
                                             l_to_read);
                if(l_s != 0)
                {
                        m_init_phase_2 = true;
                        return WAFLZ_STATUS_OK;
                }
                if(!l_rd_count)
                {
                        continue;
                }
                // -------------------------------------------------
                // if the profile has json parser enabled, check for
                // mismatch between content-type and actual content
                // We only check for json structure. Can extend it to
                // xml if this fixes some false positives
                // -------------------------------------------------
                if(m_parse_json &&
                   l_is_url_encoded)
                {
                        if(infer_is_json(l_buf, l_rd_count))
                        {
                                delete m_body_parser;
                                m_body_parser = NULL;
                                // -------------------------------------------------
                                // Change parser to json
                                // -------------------------------------------------
                                m_body_parser = new parser_json(this);
                                l_s = m_body_parser->init();
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        // do nothing...
                                        return WAFLZ_STATUS_ERROR;
                                }
                        }
                        // -------------------------------------------------
                        // Check only once in this while loop
                        // -------------------------------------------------
                        l_is_url_encoded = false;
                }
                // -----------------------------------------
                // process chunk
                // -----------------------------------------
                l_s = m_body_parser->process_chunk(l_buf, l_rd_count);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        //NDBG_PRINT("error m_body_parser->process_chunk()\n");
                        // Set request body error var in tx map and return
                        m_cx_tx_map["REQBODY_ERROR"] = "1";
                        m_init_phase_2 = true;
                        return WAFLZ_STATUS_OK;
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
                m_init_phase_2 = true;
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
        m_init_phase_2 = true;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t rqst_ctx::append_rqst_info(waflz_pb::event &ao_event, geoip2_mmdb &a_geoip2_mmdb)
{
        const char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        int32_t l_s;
        waflz_pb::request_info *l_request_info = ao_event.mutable_req_info();
        // -------------------------------------------------
        // Epoch time
        // -------------------------------------------------
        uint32_t l_now_s = get_time_s();
        uint32_t l_now_ms = get_time_ms();
        waflz_pb::request_info_timespec_t *l_epoch = l_request_info->mutable_epoch_time();
        l_epoch->set_sec(l_now_s);
        l_epoch->set_nsec(l_now_ms);
        // -------------------------------------------------
        // set headers...
        // -------------------------------------------------
#define _SET_HEADER(_header, _val) do { \
        l_d.m_data = _header; \
        l_d.m_len = sizeof(_header); \
        data_map_t::const_iterator i_h = l_hm.find(l_d); \
        if(i_h != l_hm.end()) \
        { \
                l_headers->set_##_val(i_h->second.m_data, i_h->second.m_len); \
        } \
} while(0)
#define _SET_IF_EXIST_STR(_field, _proto) do { \
        if(_field.m_data && \
           _field.m_len) { \
                l_request_info->set_##_proto(_field.m_data, _field.m_len); \
        } } while(0)
#define _SET_IF_EXIST_INT(_field, _proto) do { \
                l_request_info->set_##_proto(_field); \
        } while(0)
        // -------------------------------------------------
        // headers...
        // -------------------------------------------------
        waflz_pb::request_info::common_header_t* l_headers = l_request_info->mutable_common_header();
        const data_map_t &l_hm = m_header_map;
        data_t l_d;
        _SET_HEADER("Referer", referer);
        _SET_HEADER("User-Agent", user_agent);
        _SET_HEADER("Host", host);
        _SET_HEADER("X-Forwarded-For", x_forwarded_for);
        _SET_HEADER("Content-Type", content_type);
        // -------------------------------------------------
        // others...
        // -------------------------------------------------
        _SET_IF_EXIST_STR(m_src_addr, virt_remote_host);
        _SET_IF_EXIST_INT(m_port, server_canonical_port);
        _SET_IF_EXIST_STR(m_uri, orig_url);
        _SET_IF_EXIST_STR(m_url, url);
        _SET_IF_EXIST_STR(m_query_str, query_string);
        _SET_IF_EXIST_STR(m_method, request_method);
        // -------------------------------------------------
        // Local address
        // -------------------------------------------------
        
        if(m_callbacks && m_callbacks->m_get_rqst_local_addr_cb)
        {
                GET_RQST_DATA(m_callbacks->m_get_rqst_local_addr_cb);
                if (l_buf_len > 0)
                {
                        l_request_info->set_local_addr(l_buf, l_buf_len);
                }
        }
        // -------------------------------------------------
        // apparent cache status
        // -------------------------------------------------
        if(m_callbacks && m_callbacks->m_get_rqst_apparent_cache_status_cb)
        {
                uint32_t l_log_status = 0;
                l_s = m_callbacks->m_get_rqst_apparent_cache_status_cb(&l_log_status, m_ctx);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_apparent_cache_status_cb");
                }
                l_request_info->set_apparent_cache_log_status(static_cast <waflz_pb::request_info::log_status_t>(l_log_status));
        }
        // -------------------------------------------------
        // Bytes out
        // -------------------------------------------------
        if(m_callbacks && m_callbacks->m_get_rqst_bytes_out_cb)
        {
                uint32_t l_bytes_out;
                l_s =  m_callbacks->m_get_rqst_bytes_out_cb(&l_bytes_out, m_ctx);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_bytes_out_cb");
                }
                l_request_info->set_bytes_out(l_bytes_out);
        }
        // -------------------------------------------------
        // Bytes in
        // -------------------------------------------------
        if(m_callbacks && m_callbacks->m_get_rqst_bytes_in_cb)
        {
                uint32_t l_bytes_in;
                l_s =  m_callbacks->m_get_rqst_bytes_in_cb(&l_bytes_in, m_ctx);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_bytes_in_cb");
                }
                l_request_info->set_bytes_in(l_bytes_in);
        }
        // -------------------------------------------------
        // REQ_UUID
        // -------------------------------------------------
        if(m_req_uuid.m_len > 0)
        {
                l_request_info->set_req_uuid(m_req_uuid.m_data, m_req_uuid.m_len);
        }
        // -------------------------------------------------
        // Customer ID
        // -------------------------------------------------
        if(m_callbacks && m_callbacks->m_get_cust_id_cb)
        {
                uint32_t l_cust_id;
                l_s =  m_callbacks->m_get_cust_id_cb(&l_cust_id, m_ctx);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_cust_id_cb");
                }
                l_request_info->set_customer_id(l_cust_id);
        }
        // -------------------------------------------------
        // GEOIP info
        // -------------------------------------------------
        data_t l_cn_name;
        data_t l_city_name;
        l_cn_name.m_data = NULL;
        l_city_name.m_data = NULL;
        l_cn_name.m_len = 0;
        l_city_name.m_len = 0;
        // -------------------------------------------------
        // We only do lookup when we have an event. This is
        // to avoid uneccessary lookups, init_phase_1 does
        // one lookup for country code and asn. Since city
        // name and country names are for logging only, we
        // do that separately here.
        // -------------------------------------------------
        a_geoip2_mmdb.get_country_city_name(&l_cn_name.m_data, l_cn_name.m_len, &l_city_name.m_data, l_city_name.m_len, m_src_addr.m_data, m_src_addr.m_len);
        if(l_cn_name.m_data &&
           l_cn_name.m_len > 0)
        {
                ao_event.set_geoip_country_name(l_cn_name.m_data, l_cn_name.m_len);
        }
        if(l_city_name.m_data &&
           l_city_name.m_len > 0)
        {
                ao_event.set_geoip_city_name(l_city_name.m_data, l_city_name.m_len);
        }
        if(m_geo_cn2.m_data &&
           m_geo_cn2.m_len > 0)
        {
                 ao_event.set_geoip_country_code2(m_geo_cn2.m_data, m_geo_cn2.m_len);
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
//: ----------------------------------------------------------------------------
//: \details C binding for third party lib to cleanup rqst_ctx object after 
//:          every request is processed
//: \return  0: success
//: \param   a_rqst_ctx: rqst_ctx object
//: ----------------------------------------------------------------------------
extern "C" int32_t rqst_ctx_cleanup(rqst_ctx *a_rqst_ctx)
{
        if(a_rqst_ctx)
        {
                delete a_rqst_ctx;
                a_rqst_ctx = NULL;
        }
        return WAFLZ_STATUS_OK;
}
}
