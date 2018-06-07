//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    waf.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    09/30/2015
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
// ---------------------------------------------------------
// proto
// ---------------------------------------------------------
#include "event.pb.h"
#include "request_info.pb.h"
#include "waflz/_waf.h"
#include "waflz/rqst_ctx.h"
#include "waflz/def.h"
#include "support/time_util.h"
#include "op/regex.h"
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define GET_RQST_DATA(_cb) do { \
        l_buf = NULL; \
        l_buf_len = 0; \
        if(rqst_ctx::_cb) { \
                l_s = rqst_ctx::_cb(&l_buf, l_buf_len, a_ctx); \
                if(l_s != 0) { \
                        return WAFLZ_STATUS_ERROR; \
                } \
        } \
} while(0)
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static void clear_ignore_list(pcre_list_t &a_pcre_list)
{
        for(pcre_list_t::iterator i_r = a_pcre_list.begin();
            i_r != a_pcre_list.end();
            ++i_r)
        {
                if(*i_r)
                {
                        delete *i_r;
                        *i_r = NULL;
                }
        }
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
_waf::_waf(engine &a_engine):
        m_il_query(),
        m_il_header(),
        m_il_cookie(),
        m_is_initd(false),
        m_engine(a_engine),
        m_id("NA"),
        m_name("NA"),
        m_owasp_ruleset_version(0),
        m_no_log_matched(false)
{
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
_waf::~_waf()
{
        clear_ignore_list(m_il_query);
        clear_ignore_list(m_il_header);
        clear_ignore_list(m_il_cookie);
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t _waf::regex_list_add(const std::string &a_regex,
                             pcre_list_t &a_pcre_list)
{
        int32_t l_s;
        regex *l_regex = new regex();
        l_s = l_regex->init(a_regex.c_str(), a_regex.length());
        if(l_s != WAFLZ_STATUS_OK)
        {
                const char *l_err_ptr;
                int l_err_off;
                l_regex->get_err_info(&l_err_ptr, l_err_off);
                delete l_regex;
                l_regex = NULL;
                //WAFLZ_PERROR(m_err_msg, "init failed for regex: '%s' in access_settings ignore list. Reason: %s -offset: %d\n",
                //            a_regex.c_str(),
                //            l_err_ptr,
                //            l_err_off);
                return WAFLZ_STATUS_ERROR;
        }
        // add to map
        a_pcre_list.push_back(l_regex);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t _waf::append_rqst_info(waflz_pb::event &ao_event, void *a_ctx)
{
        const char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        int32_t l_s;
        waflz_pb::request_info *l_request_info = ao_event.mutable_req_info();
        // -------------------------------------------------
        // Common headers
        // -------------------------------------------------
        if(rqst_ctx::s_get_rqst_header_w_key_cb)
        {
                waflz_pb::request_info::common_header_t* l_headers = l_request_info->mutable_common_header();
                // -----------------------------------------
                // Referer
                // -----------------------------------------
                const char *l_key = "Referer";
                l_s = rqst_ctx::s_get_rqst_header_w_key_cb(&l_buf, l_buf_len, a_ctx, l_key, strlen(l_key));
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_w_key_cb: key: %s", l_key);
                }
                if(l_buf &&
                   l_buf_len)
                {
                        l_headers->set_referer(l_buf, l_buf_len);
                }
                // -----------------------------------------
                // User-Agent
                // -----------------------------------------
                l_key = "User-Agent";
                l_s = rqst_ctx::s_get_rqst_header_w_key_cb(&l_buf, l_buf_len, a_ctx, l_key, strlen(l_key));
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_w_key_cb: key: %s", l_key);
                }
                if(l_buf &&
                   l_buf_len)
                {
                        l_headers->set_user_agent(l_buf, l_buf_len);
                }
                // -----------------------------------------
                // Host
                // -----------------------------------------
                l_key = "Host";
                l_s = rqst_ctx::s_get_rqst_header_w_key_cb(&l_buf, l_buf_len, a_ctx, l_key, strlen(l_key));
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_w_key_cb: key: %s", l_key);
                }
                if(l_buf &&
                   l_buf_len)
                {
                        l_headers->set_host(l_buf, l_buf_len);
                }
                // -----------------------------------------
                // X-Forwarded-For
                // -----------------------------------------
                l_key = "X-Forwarded-For";
                l_s = rqst_ctx::s_get_rqst_header_w_key_cb(&l_buf, l_buf_len, a_ctx, l_key, strlen(l_key));
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_w_key_cb: key: %s", l_key);
                }
                if(l_buf &&
                   l_buf_len)
                {
                        l_headers->set_x_forwarded_for(l_buf, l_buf_len);
                }
                // -----------------------------------------
                // Content-type
                // -----------------------------------------
                l_key = "Content-type";
                l_s = rqst_ctx::s_get_rqst_header_w_key_cb(&l_buf, l_buf_len, a_ctx, l_key, strlen(l_key));
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_w_key_cb: key: %s", l_key);
                }
                if(l_buf &&
                   l_buf_len)
                {
                        l_headers->set_content_type(l_buf, l_buf_len);
                }
        }
        // -------------------------------------------------
        // Virtual remote host
        // -------------------------------------------------
        GET_RQST_DATA(s_get_rqst_src_addr_cb);
        if (l_buf_len > 0)
        {
                l_request_info->set_virt_remote_host(l_buf, l_buf_len);
        }
        // -------------------------------------------------
        // Local address
        // -------------------------------------------------
        GET_RQST_DATA(s_get_rqst_local_addr_cb);
        if (l_buf_len > 0)
        {
                l_request_info->set_local_addr(l_buf, l_buf_len);
        }
        // -------------------------------------------------
        // Server canonical port
        // -------------------------------------------------
        if(rqst_ctx::s_get_rqst_canonical_port_cb)
        {
                uint32_t l_canonical_port;
                l_s = rqst_ctx::s_get_rqst_canonical_port_cb(l_canonical_port, a_ctx);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_canonical_port_cb");
                }
                l_request_info->set_server_canonical_port(l_canonical_port);
        }
        // -------------------------------------------------
        // File size
        // TODO: Not logged in waf events
        // -------------------------------------------------
        // -------------------------------------------------
        // APPARENT_CACHE_STATUS
        // TODO: check again
        // -------------------------------------------------
        if(rqst_ctx::s_get_rqst_apparent_cache_status_cb)
        {
                uint32_t l_log_status = 0;
                l_s = rqst_ctx::s_get_rqst_apparent_cache_status_cb(l_log_status, a_ctx);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_apparent_cache_status_cb");
                }
                l_request_info->set_apparent_cache_log_status(static_cast <waflz_pb::request_info::log_status_t>(l_log_status));
        }
        // -------------------------------------------------
        // Status
        // -------------------------------------------------
        // -------------------------------------------------
        // Bytes out
        // -------------------------------------------------
        if(rqst_ctx::s_get_rqst_bytes_out_cb)
        {
                uint32_t l_bytes_out;
                l_s =  rqst_ctx::s_get_rqst_bytes_out_cb(l_bytes_out, a_ctx);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_bytes_out_cb");
                }
                l_request_info->set_bytes_out(l_bytes_out);
        }
        // -------------------------------------------------
        // Bytes in
        // -------------------------------------------------
        if(rqst_ctx::s_get_rqst_bytes_in_cb)
        {
                uint32_t l_bytes_in;
                l_s =  rqst_ctx::s_get_rqst_bytes_in_cb(l_bytes_in, a_ctx);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_bytes_in_cb");
                }
                l_request_info->set_bytes_in(l_bytes_in);
        }
        // -------------------------------------------------
        // Epoch time
        // -------------------------------------------------
        uint32_t l_now_s = get_time_s();
        uint32_t l_now_ms = get_time_ms();
        waflz_pb::request_info_timespec_t *l_epoch = l_request_info->mutable_epoch_time();
        l_epoch->set_sec(l_now_s);
        l_epoch->set_nsec(l_now_ms);
        // -------------------------------------------------
        // Orig url
        // -------------------------------------------------
        GET_RQST_DATA(s_get_rqst_uri_cb);
        if (l_buf_len > 0)
        {
                l_request_info->set_orig_url(l_buf, l_buf_len);
        }
        // -------------------------------------------------
        // Url
        // -------------------------------------------------
        GET_RQST_DATA(s_get_rqst_url_cb);
        if (l_buf_len > 0)
        {
                l_request_info->set_url(l_buf, l_buf_len);
        }
        // -------------------------------------------------
        // Query string
        // -------------------------------------------------
        GET_RQST_DATA(s_get_rqst_query_str_cb);
        if (l_buf_len > 0)
        {
                l_request_info->set_query_string(l_buf, l_buf_len);
        }
        // -------------------------------------------------
        // Request ID
        // -------------------------------------------------
        if(rqst_ctx::s_get_rqst_req_id_cb)
        {
                uint32_t l_req_id;
                l_s =  rqst_ctx::s_get_rqst_req_id_cb(l_req_id, a_ctx);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_req_id_cb");
                }
                l_request_info->set_request_id(l_req_id);
        }
        // -------------------------------------------------
        // REQ_UUID
        // -------------------------------------------------
        GET_RQST_DATA(s_get_rqst_id_cb);
        if (l_buf_len > 0)
        {
                l_request_info->set_req_uuid(l_buf, l_buf_len);
        }
        // -------------------------------------------------
        // HTTP Method
        // -------------------------------------------------
        GET_RQST_DATA(s_get_rqst_method_cb);
        if (l_buf_len > 0)
        {
                l_request_info->set_request_method(l_buf, l_buf_len);
        }
        // -------------------------------------------------
        // Customer ID
        // -------------------------------------------------
        if(rqst_ctx::s_get_rqst_req_id_cb)
        {
                uint32_t l_cust_id;
                l_s =  rqst_ctx::s_get_cust_id_cb(l_cust_id, a_ctx);
                if(l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_cust_id_cb");
                }
                l_request_info->set_customer_id(l_cust_id);
        }
        return WAFLZ_STATUS_OK;
}
}
