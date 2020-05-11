//! ----------------------------------------------------------------------------
//! Copyright (C) 2016 Verizon.  All Rights Reserved.
//! All Rights Reserved
//:
//! @file:    config.cc
//! @details: TODO
//! @author:  Reed P. Morrison
//! @date:    11/30/2016
//:
//!   Licensed under the Apache License, Version 2.0 (the "License");
//!   you may not use this file except in compliance with the License.
//!   You may obtain a copy of the License at
//:
//!       http://www.apache.org/licenses/LICENSE-2.0
//:
//!   Unless required by applicable law or agreed to in writing, software
//!   distributed under the License is distributed on an "AS IS" BASIS,
//!   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//!   See the License for the specific language governing permissions and
//!   limitations under the License.
//:
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "support/time_util.h"
#include "support/ndebug.h"
#include "support/string_util.h"
#include "support/base64.h"
#include "jspb/jspb.h"
#include "waflz/def.h"
#include "waflz/limit.h"
#include "waflz/kv_db.h"
#include "waflz/rqst_ctx.h"
#include "waflz/render.h"
#include "waflz/scopes.h"
#include "waflz/enforcer.h"
#include "waflz/config.h"
#include "rapidjson/document.h"
#include "rapidjson/error/error.h"
#include "rapidjson/error/en.h"
#include "limit.pb.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _GET_HEADER(_header) do { \
    l_d.m_data = _header; \
    l_d.m_len = sizeof(_header); \
    data_map_t::const_iterator i_h = a_ctx->m_header_map.find(l_d); \
    if(i_h != a_ctx->m_header_map.end()) \
    { \
            l_v.m_data = i_h->second.m_data; \
            l_v.m_len = i_h->second.m_len; \
    } \
    } while(0)
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
// the maximum size of the json defining configuration for a ddos enforcement (1MB)
#define _CONFIG_MAX_SIZE (1<<20)
#define _MAX_KEY_LEN 1024
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! @details return short date in form "<mm>/<dd>/<YYYY>"
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
static const char *get_date_short_str(void)
{
        // TODO thread caching???
        static char s_date_str[128];
        time_t l_time = time(NULL);
        struct tm* l_tm = localtime(&l_time);
        if(0 == strftime(s_date_str, sizeof(s_date_str), "%m/%d/%Y", l_tm))
        {
                return "1/1/1970";
        }
        else
        {
                return s_date_str;
        }
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! ----------------------------------------------------------------------------
config::config(kv_db &a_db,
               challenge& a_challenge,
               bool a_case_insensitive_headers):
        rl_obj(a_case_insensitive_headers),
        m_db(a_db),
        m_challenge(a_challenge),
        m_enfx(NULL),
        m_exceed_key_set()
{
        m_enfx = new enforcer(m_lowercase_headers);
}
//! ----------------------------------------------------------------------------
//! @details dtor
//! ----------------------------------------------------------------------------
config::~config()
{
        if(m_enfx) { delete m_enfx; m_enfx = NULL; }
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t config::load()
{
        int32_t l_s;
        // ------------------------------------------------
        // validate
        // ------------------------------------------------
        l_s = validate();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // ------------------------------------------------
        // compile
        // ------------------------------------------------
        l_s = compile();
        //TRC_DEBUG("whole config %s", m_pb->DebugString().c_str());
        if(l_s != WAFLZ_STATUS_OK)
        {
                //TRC_DEBUG("error in compile");
                return WAFLZ_STATUS_ERROR;
        }
        // ------------------------------------------------
        // remove "always_on" limits from config
        // config and add it to m_enfx with no expiry
        // ------------------------------------------------
        int32_t i_r = 0;
        while(i_r < m_pb->limits_size())
        {
                waflz_pb::limit* i_r_ptr = m_pb->mutable_limits(i_r);
                if(!i_r_ptr->has_always_on() ||
                   !i_r_ptr->always_on())
                {
                        ++i_r;
                        continue;
                }
                waflz_pb::config *l_cfg = new waflz_pb::config();
                l_cfg->set_id("NA");
                l_cfg->set_name("NA");
                l_cfg->set_type(waflz_pb::config_type_t_ENFORCER);
                l_cfg->set_customer_id(m_pb->customer_id());
                //l_cfg->set_enabled_date(get_date_short_str());
                // ----------------------------------------
                // copy limit info
                // ----------------------------------------
                waflz_pb::limit* l_limit = l_cfg->add_limits();
                l_limit->CopyFrom(*i_r_ptr);
                l_limit->clear_keys();
                //-----------------------------------------
                // Remove enforcement duration
                //-----------------------------------------
                if(l_limit->has_action())
                {
                        waflz_pb::enforcement* l_e = l_limit->mutable_action();
                        l_e->set_duration_sec(3600);
                        l_e->clear_start_time_ms();
                }
                //-----------------------------------------
                // add it to enfcr
                //-----------------------------------------
                l_s = m_enfx->merge(*l_cfg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_cfg){delete l_cfg; l_cfg = NULL;}
                        WAFLZ_PERROR(m_err_msg, "enforcers merge failed");
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_cfg) { delete l_cfg; l_cfg = NULL;}
                //-----------------------------------------
                // remove limit from config
                //-----------------------------------------
                l_s = limit_remove(*m_pb, i_r);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "Error removing limit from config");
                        return WAFLZ_STATUS_ERROR;
                }
                ++i_r;
        }
        // -------------------------------------------------
        // convert customer to uint64
        // -------------------------------------------------
        const std::string &l_cust_id_str = get_customer_id();
        uint64_t l_cust_id = 0;
        l_s = convert_hex_to_uint(l_cust_id, l_cust_id_str.c_str());
        if(l_s == WAFLZ_STATUS_OK)
        {
                // do nothing???
        }
        m_pb->set__customer_id_int(l_cust_id);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t config::validate(void)
{
        // -------------------------------------------------
        // validate pb
        // -------------------------------------------------
        if(!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate type
        // -------------------------------------------------
        if(!m_pb->has_type())
        {
                WAFLZ_PERROR(m_err_msg, "missing type field");
                return WAFLZ_STATUS_ERROR;
        }
        if(m_pb->type() != waflz_pb::config_type_t_CONFIG)
        {
                WAFLZ_PERROR(m_err_msg, "type: %d != config_type_t_CONFIG", m_pb->type());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate id
        // -------------------------------------------------
        if(!m_pb->has_id() ||
            m_pb->id().empty())
        {
                WAFLZ_PERROR(m_err_msg, "missing id field or empty");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate customer id
        // -------------------------------------------------
        if(!m_pb->has_customer_id() ||
            m_pb->customer_id().empty())
        {
                WAFLZ_PERROR(m_err_msg, "missing customer_id field or empty");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate fields in limits
        // -------------------------------------------------
        for(int i_r = 0; i_r < m_pb->limits_size(); ++i_r)
        {
                waflz_pb::limit *i_l_ptr = m_pb->mutable_limits(i_r);
                if(!i_l_ptr->has_id() ||
                    i_l_ptr->id().empty())
                {
                        WAFLZ_PERROR(m_err_msg, "limit missing id field or empty");
                        return WAFLZ_STATUS_ERROR;
                }
                if(i_l_ptr->has_always_on() &&
                   i_l_ptr->always_on())
                {
                        continue;
                }
                if(!i_l_ptr->has_num() ||
                   (i_l_ptr->num() <= 0))
                {
                        WAFLZ_PERROR(m_err_msg, "limit missing num field or num is <= 0");
                        return WAFLZ_STATUS_ERROR;
                }
                if(!i_l_ptr->has_duration_sec())
                {
                        WAFLZ_PERROR(m_err_msg, "limit missing duration field");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t config::load(void *a_js)
{
        if(!a_js)
        {
                WAFLZ_PERROR(m_err_msg, "a_js == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s;
        const rapidjson::Value &l_js = *((rapidjson::Value *)a_js);
        // -------------------------------------------------
        // create pbuf...
        // -------------------------------------------------
        l_s = update_from_json(*m_pb, l_js);
        if(l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // load and validate
        // -------------------------------------------------
        l_s = load();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t config::load(const char *a_buf,
                     uint32_t a_buf_len)
{
        if(a_buf_len > _CONFIG_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                             a_buf_len,
                             _CONFIG_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        rapidjson::Document *l_js = new rapidjson::Document();
        rapidjson::ParseResult l_ok;
        l_ok = l_js->Parse(a_buf, a_buf_len);
        if (!l_ok)
        {
                WAFLZ_PERROR(m_err_msg, "JSON parse error: %s (%d)",
                             rapidjson::GetParseError_En(l_ok.Code()), (int)l_ok.Offset());
                if(l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // load...
        // -------------------------------------------------
        int32_t l_s;
        l_s = load((void *)l_js);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_js) { delete l_js; l_js = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        if(l_js) { delete l_js; l_js = NULL; }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
const std::string& config::get_last_modified_date()
{
        if(m_pb &&
           m_pb->has_last_modified_date())
        {
                return m_pb->last_modified_date();
        }
        static std::string s_ret = "";
        return s_ret;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t config::process_enfx(const waflz_pb::enforcement** ao_enfcmnt,
                             bool& ao_pass,
                             rqst_ctx* a_ctx)
{
        if(!ao_enfcmnt)
        {
                return WAFLZ_STATUS_ERROR;
        }
        if(!m_enfx)
        {
                return WAFLZ_STATUS_OK;
        }
        int32_t l_s;
        const waflz_pb::enforcement *l_enfcmnt = NULL;
        l_s = m_enfx->process(&l_enfcmnt, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing enforcer process");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // process enforcement
        // -------------------------------------------------
        if(!l_enfcmnt ||
           !l_enfcmnt->has_enf_type())
        {
                return WAFLZ_STATUS_OK;
        }
        ::waflz_pb::enforcement_type_t l_type = l_enfcmnt->enf_type();
        // -------------------------------------------------
        // *************************************************
        //                   C H E C K
        // *************************************************
        // -------------------------------------------------
        switch(l_type)
        {
        // -------------------------------------------------
        // BROWSER_CHALLENGE
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_BROWSER_CHALLENGE:
        {
                //NDBG_PRINT("check valid for...\n%s\n", l_enfcmnt->DebugString().c_str());
                // -----------------------------------------
                // check cookie -verify browser challenge
                // -----------------------------------------
                // default to valid for 10 min
                uint32_t l_valid_for_s = 600;
                if(l_enfcmnt->has_valid_for_sec())
                {
                        l_valid_for_s = l_enfcmnt->valid_for_sec();
                }
                //NDBG_PRINT("valid for: %d\n", (int)l_valid_for_s);
                int32_t l_s;
                l_s = m_challenge.verify(ao_pass, l_valid_for_s, a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // do nothing -re-issue challenge
                }
                break;
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        default:
        {
                break;
        }
        }
        // -------------------------------------------------
        // if pass finish...
        // -------------------------------------------------
        if(ao_pass)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // if has status set
        // -------------------------------------------------
        if(l_enfcmnt->has_status())
        {
                a_ctx->m_resp_status = l_enfcmnt->status();
        }
        // done...
        *ao_enfcmnt = l_enfcmnt;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t config::process(const waflz_pb::enforcement** ao_enfcmnt,
                        const waflz_pb::limit** ao_limit,
                        rqst_ctx* a_ctx)

{
        if(!ao_enfcmnt)
        {
                WAFLZ_PERROR(m_err_msg, "ao_enfx == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(!m_enfx)
        {
                WAFLZ_PERROR(m_err_msg, "m_enfx == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        *ao_enfcmnt = NULL;
        if(ao_limit) { *ao_limit = NULL; }
        // -------------------------------------------------
        // process enforcer
        // -------------------------------------------------
        int32_t l_s;
        bool l_pass = false;
        l_s = process_enfx(ao_enfcmnt, l_pass, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check for pass or event
        // -------------------------------------------------
        if(l_pass ||
           *ao_enfcmnt)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // process config
        // -------------------------------------------------
        waflz_pb::config *l_cfg = NULL;
        l_s = process_config(&l_cfg, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing config process");
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_cfg)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // merge enfx
        // -------------------------------------------------
        //NDBG_OUTPUT("l_enfx: %s\n", l_enfcr->ShortDebugString().c_str());
        l_s = m_enfx->merge(*l_cfg);
        // TODO -return enforcer...
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", m_enfx->get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        if(l_cfg) { delete l_cfg; l_cfg = NULL; }
        // -------------------------------------------------
        // get enforcer
        // -------------------------------------------------
        if(ao_limit)
        {
                const waflz_pb::config* l_enfx = m_enfx->get_pb();
                if(l_enfx &&
                   l_enfx->limits_size())
                {
                        *ao_limit = &(l_enfx->limits(l_enfx->limits_size() - 1));
                }
        }
        // -------------------------------------------------
        // process enforcer
        // -------------------------------------------------
        l_s = process_enfx(ao_enfcmnt, l_pass, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        //NDBG_PRINT("ao_event: %p\n", *ao_event);
        // -------------------------------------------------
        // check for pass or event
        // -------------------------------------------------
        if(l_pass ||
           *ao_enfcmnt)
        {
                return WAFLZ_STATUS_OK;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details Populates rl event protobuf
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t config::generate_alert(waflz_pb::alert** ao_alert,
                               rqst_ctx* a_ctx)
{
        waflz_pb::alert* l_at = new waflz_pb::alert();
        // -------------------------------------------------
        // Get the matched limit
        // -------------------------------------------------
        if(a_ctx->m_limit)
        {
                waflz_pb::limit *l_ev_limit = l_at->mutable_limit();
                // TODO -only copy in meta -ie exclude enforcement body info...
                l_ev_limit->CopyFrom(*(a_ctx->m_limit));
                // -----------------------------------------
                // copy in first enf
                // -----------------------------------------
                if(a_ctx->m_limit->has_action())
                {
                        l_at->mutable_action()->CopyFrom(a_ctx->m_limit->action());
                }
        }
        // -------------------------------------------------
        // Get the matched limit
        // -------------------------------------------------
        if(a_ctx->m_limit)
        {
                waflz_pb::limit *l_ev_limit = l_at->mutable_limit();
                l_ev_limit->CopyFrom(*(a_ctx->m_limit));
        }
        // -------------------------------------------------
        // Get request specific info
        // -------------------------------------------------
        if(!a_ctx)
        {
                return WAFLZ_STATUS_OK;
        }
        waflz_pb::request_info *l_request_info = l_at->mutable_req_info();
        // -------------------------------------------------
        // Epoch time
        // -------------------------------------------------
        uint32_t l_now_s = get_time_s();
        uint32_t l_now_ms = get_time_ms();
        waflz_pb::request_info_timespec_t *l_epoch = l_request_info->mutable_epoch_time();
        l_epoch->set_sec(l_now_s);
        l_epoch->set_nsec(l_now_ms);
        // -------------------------------------------------
        // common headers
        // -------------------------------------------------
        //TRC_DEBUG("setting headers\n");
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
        if(a_ctx->_field.m_data && \
           a_ctx->_field.m_len) { \
                l_request_info->set_##_proto(a_ctx->_field.m_data, a_ctx->_field.m_len); \
        } } while(0)
#define _SET_IF_EXIST_INT(_field, _proto) do { \
                l_request_info->set_##_proto(a_ctx->_field); \
        } while(0)
        // -------------------------------------------------
        // headers...
        // -------------------------------------------------
        waflz_pb::request_info::common_header_t* l_headers = l_request_info->mutable_common_header();
        const data_map_t &l_hm = a_ctx->m_header_map;
        data_t l_d;
        _SET_HEADER("Referer", referer);
        _SET_HEADER("User-Agent", user_agent);
        _SET_HEADER("Host", host);
        _SET_HEADER("X-Forwarded-For", x_forwarded_for);
        // -------------------------------------------------
        // others...
        // -------------------------------------------------
        _SET_IF_EXIST_STR(m_src_addr, virt_remote_host);
        _SET_IF_EXIST_STR(m_local_addr, local_addr);
        _SET_IF_EXIST_INT(m_port, server_canonical_port);
        _SET_IF_EXIST_STR(m_uri, orig_url);
        _SET_IF_EXIST_STR(m_url, url);
        _SET_IF_EXIST_STR(m_query_str, query_string);
        _SET_IF_EXIST_STR(m_method, request_method);
        _SET_IF_EXIST_STR(m_req_uuid, req_uuid);
        _SET_IF_EXIST_INT(m_bytes_out, bytes_out);
        _SET_IF_EXIST_INT(m_bytes_in, bytes_in);
        // -------------------------------------------------
        // TODO -apologies for enum casting...
        // -------------------------------------------------
        l_request_info->set_apparent_cache_log_status(static_cast <waflz_pb::request_info::log_status_t>(a_ctx->m_apparent_cache_status));
        // -------------------------------------------------
        // set customer id...
        // -------------------------------------------------
        l_at->mutable_req_info()->set_customer_id(m_pb->_customer_id_int());
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        *ao_alert = l_at;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t config::merge(waflz_pb::config &ao_cfg)
{
        int32_t l_s;
        //NDBG_OUTPUT("l_enfx: %s\n", l_enfx->ShortDebugString().c_str());
        l_s = m_enfx->merge(ao_cfg);
        // TODO -return enforcer...
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", m_enfx->get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t config::add_limit_with_key(waflz_pb::limit &ao_limit,
                                  uint16_t a_key,
                                  rqst_ctx *a_ctx)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Set operator to streq for all
        // -------------------------------------------------
        const char *l_data = NULL;
        uint32_t l_len = 0;
        switch(a_key)
        {
        // -------------------------------------------------
        // ip
        // -------------------------------------------------
        case waflz_pb::limit_key_t_IP:
        {
                l_data = a_ctx->m_src_addr.m_data;
                l_len = a_ctx->m_src_addr.m_len;
                break;
        }
        // -------------------------------------------------
        // user-agent
        // -------------------------------------------------
        case waflz_pb::limit_key_t_USER_AGENT:
        {
                if(!a_ctx)
                {
                        break;
                }
                data_t l_d;
                data_t l_v;
                _GET_HEADER("User-Agent");
                l_data = l_v.m_data;
                l_len = l_v.m_len;
                break;
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        default:
        {
                WAFLZ_PERROR(m_err_msg, "unrecognized dimension type: %u", a_key);
                return WAFLZ_STATUS_ERROR;
        }
        }
        // if no data -no limit
        if(!l_data ||
           (l_len == 0))
        {
                return WAFLZ_STATUS_OK;
        }
        // Add limit for any data
        waflz_pb::condition *l_c = NULL;
        if(ao_limit.condition_groups_size() > 0)
        {
                l_c = ao_limit.mutable_condition_groups(0)->add_conditions();
        }
        else
        {
                l_c = ao_limit.add_condition_groups()->add_conditions();
        }
        // -------------------------------------------------
        // set operator
        // -------------------------------------------------
        // always STREQ
        waflz_pb::op_t* l_operator = l_c->mutable_op();
        l_operator->set_type(waflz_pb::op_t_type_t_STREQ);
        l_operator->set_value(l_data, l_len);
        // -------------------------------------------------
        // set var
        // -------------------------------------------------
        waflz_pb::condition_target_t* l_var = l_c->mutable_target();
        switch(a_key)
        {
        // -------------------------------------------------
        // ip
        // -------------------------------------------------
        case waflz_pb::limit_key_t_IP:
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REMOTE_ADDR);
                break;
        }
        // -------------------------------------------------
        // user-agent
        // -------------------------------------------------
        case waflz_pb::limit_key_t_USER_AGENT:
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REQUEST_HEADERS);
                l_var->mutable_value()->assign("User-Agent");
                break;
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        default:
        {
                break;
        }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t config::add_exceed_limit(waflz_pb::config **ao_cfg,
                                const std::string &a_cust_id,
                                const waflz_pb::limit& a_limit,
                                const waflz_pb::condition_group *a_condition_group,
                                rqst_ctx *a_ctx)
{
        if(!ao_cfg)
        {
                WAFLZ_PERROR(m_err_msg, "enforcer ptr NULL.");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create enforcer if null
        // -------------------------------------------------
        if(*ao_cfg == NULL)
        {
                waflz_pb::config *l_cfg = new waflz_pb::config();
                l_cfg->set_id("NA");
                l_cfg->set_name("NA");
                l_cfg->set_type(waflz_pb::config_type_t_ENFORCER);
                l_cfg->set_customer_id(a_cust_id);
                l_cfg->set_enabled_date(get_date_short_str());
                *ao_cfg = l_cfg;
        }
        // -------------------------------------------------
        // populate limit info
        // -------------------------------------------------
        waflz_pb::limit* l_limit = (*ao_cfg)->add_limits();
        l_limit->set_id(a_limit.id());
        if(a_limit.has_name())
        { l_limit->set_name(a_limit.name()); }
        else
        {
                l_limit->set_name("NA");
        }
        l_limit->set_disabled(false);
        // -------------------------------------------------
        // copy scope
        // -------------------------------------------------
        if(a_limit.has_scope())
        {
                l_limit->mutable_scope()->CopyFrom(a_limit.scope());
        }
        // -------------------------------------------------
        // copy "the limit"
        // -------------------------------------------------
        if(a_condition_group)
        {
                waflz_pb::condition_group *l_cg = l_limit->add_condition_groups();
                l_cg->CopyFrom(*a_condition_group);
        }
        // -------------------------------------------------
        // create limits for dimensions
        // -------------------------------------------------
        for(int i_k = 0; i_k < a_limit.keys_size(); ++i_k)
        {
                int32_t l_s;
                l_s = add_limit_with_key(*l_limit,
                                        a_limit.keys(i_k),
                                        a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // copy enforcement(s)
        // -------------------------------------------------
        // TODO -code assumes single enforcement currently...
        if(!a_limit.has_action())
        {
                return WAFLZ_STATUS_ERROR;
        }
        uint64_t l_cur_time_ms = get_time_ms();
        uint32_t l_e_duration_s = 0;
        waflz_pb::enforcement *l_e = l_limit->mutable_action();
        l_e->CopyFrom(a_limit.action());
        // only id/name/type might be set
        l_e->set_start_time_ms(l_cur_time_ms);
        // TODO set percentage to 100 for now
        l_e->set_percentage(100.0);
        // -------------------------------------------------
        // duration calculation
        // -------------------------------------------------
        if(l_e->has_duration_sec())
        {
                l_e_duration_s = l_e->duration_sec();
        }
        else
        {
                l_e_duration_s = a_limit.duration_sec();
        }
        l_e->set_duration_sec(l_e_duration_s);
        l_limit->set_start_epoch_msec(l_cur_time_ms);
        l_limit->set_end_epoch_msec(l_cur_time_ms + l_e_duration_s*1000);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t config::handle_match(waflz_pb::config **ao_cfg,
                             const std::string &a_cust_id,
                             const waflz_pb::limit& a_limit,
                             const waflz_pb::condition_group *a_condition_group,
                             rqst_ctx *a_ctx)
{
        // -------------------------------------------------
        // get key for limit
        // -------------------------------------------------
        // Construct db key eg:
        //   AN:LIMIT_ID:DIM1=DIM1VAL:...DIMN=DIMNVAL
        // -------------------------------------------------
        char l_key[_MAX_KEY_LEN];
        int32_t l_s;
        l_s = get_limit_key_value(l_key,
                                  a_cust_id,
                                  a_limit,
                                  a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "Failed to generate db key for limit id: '%s'", a_limit.id().c_str());
                return WAFLZ_STATUS_ERROR;
        }
        //NDBG_PRINT("l_key: %s\n", l_key);
        // -------------------------------------------------
        // increment key value in db
        // -------------------------------------------------
        // increment one of our counters
        // this count automatically rolls over because key
        // includes bucketing information
        // gives historical data as well as auto-rollover
        // -------------------------------------------------
        int64_t l_cur_num = 0;
        l_s = m_db.increment_key(l_cur_num,
                                 l_key,
                                 a_limit.duration_sec()*1000);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "Failed to perform db key increment for limit id: '%s' key: %s",
                             a_limit.id().c_str(),
                             l_key);
                return WAFLZ_STATUS_ERROR;
        }
        //NDBG_PRINT("KEY: %s VAL: %li\n", l_key, l_cur_num);
        // TODO log?
        //TRACE("Incremented time bucket key '%s' count to: %" PRIi64, bucket_key.b_str(), l_current_number);
        // -------------------------------------------------
        // find if this key is already exceeding
        // -------------------------------------------------
        uint64_t l_key_hash = CityHash64(l_key, strlen(l_key));
        exceed_key_set_t::iterator i_k;
        i_k = m_exceed_key_set.find(l_key_hash);
        //TRC_DEBUG("=============================\n");
        //TRC_DEBUG("l_key:                   %s\n",  l_key.c_str());
        //TRC_DEBUG("l_cur_num:               %ld\n", l_cur_num);
        //TRC_DEBUG("l_key_hash:              %X\n",  l_key_hash);
        //TRC_DEBUG("m_last_match_bucket_key: %s\n",  m_last_match_bucket_key.c_str());
        //TRC_DEBUG("a_limit.limit():          %u\n",  a_limit.limit());
        // -------------------------------------------------
        // already tracking this limit as exceeder?
        // -------------------------------------------------
        if(i_k != m_exceed_key_set.end())
        {
                // TODO log?
                //TRC_DEBUG("key '%s' is already being tracked as exceeding, cur_count: %ld",
                //          l_key.c_str(),
                //         l_cur_num);
                // -----------------------------------------
                // if first time remove from list of limits
                // -----------------------------------------
                if(l_cur_num == 1)
                {
                        m_exceed_key_set.erase(i_k);
                }
                // -----------------------------------------
                // skip if there enforcement running
                // -----------------------------------------
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // limit is not already exceeding
        // -------------------------------------------------
        if(l_cur_num > (int64_t)(a_limit.num()))
        {
                // limit has been exceeded
                // TODO log?
                //TRC_DEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                //TRC_DEBUG("key '%s' add exceeds\n", l_key.c_str());
                l_s = add_exceed_limit(ao_cfg,
                                       a_cust_id,
                                       a_limit,
                                       a_condition_group,
                                       a_ctx);
                //TRC_DEBUG("key '%s' count: %ld exceeds limit of: %ld ao_enfcr: %p\n",
                //          l_key.c_str(),
                //          l_cur_num,
                //          (int64_t)a_limit.limit(),
                //          *ao_enfcr);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                m_exceed_key_set.insert(l_key_hash);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t config::process_config(waflz_pb::config **ao_cfg,
                              rqst_ctx *a_ctx)
{
        // init to null
        if(ao_cfg)
        {
                *ao_cfg = NULL;
        }
        // -------------------------------------------------
        // overall algorithm:
        //   Look up customers coordination configuration
        //
        //   For each variable limit configured -(reuse a bunch of ddos::enforcer)
        //     If a limit match indicates entire limit matched
        //       Construct db key
        //       Increment key value in db
        //       If value above limits limit
        //         Record limit being exceeded
        //   If limits exceeded for customer
        //     For each
        //       synthesize into enforcement config
        // -------------------------------------------------
        if(!m_pb)
        {
                // TODO log error reason
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // db check
        // -------------------------------------------------
        if(!m_db.get_init())
        {
                // -----------------------------------------
                // db not yet initialized -ignore request
                // -----------------------------------------
                WAFLZ_PERROR(m_err_msg, "db not yet initialized");
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // limits...
        // -------------------------------------------------
        for(int i_r = 0; i_r < m_pb->limits_size(); ++i_r)
        {
                //NDBG_PRINT("limit[%d]: process\n", i_r);
                waflz_pb::limit *i_r_ptr = m_pb->mutable_limits(i_r);
                if(!i_r_ptr)
                {
                        // TODO log error reason
                        return WAFLZ_STATUS_ERROR;
                }
                waflz_pb::limit &i_limit = *i_r_ptr;
                // -----------------------------------------
                // disabled???
                // -----------------------------------------
                if(i_limit.has_disabled() &&
                   i_limit.disabled())
                {
                        continue;
                }
                // -----------------------------------------
                // check scope
                // -----------------------------------------
                if(i_limit.has_scope())
                {
                        bool l_match = false;
                        int32_t l_s;
                        l_s = in_scope(l_match, i_limit.scope(), a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO log error reason
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(!l_match)
                        {
                                continue;
                        }
                }
                // -----------------------------------------
                // match-less limits...
                // -----------------------------------------
                if(i_limit.condition_groups_size() == 0)
                {
                        // ---------------------------------
                        // ************MATCH****************
                        // ---------------------------------
                        // TODO log?
                        //TRC_DEBUG("Matched enforcement limit completely!\n");
                        int32_t l_s;
                        l_s = handle_match(ao_cfg,
                                           m_pb->customer_id(),
                                           i_limit,
                                           NULL,
                                           a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO log error reason
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(*ao_cfg)
                        {
                                return WAFLZ_STATUS_OK;
                        }
                        continue;
                }
                // -----------------------------------------
                // limits w/condition_groups
                // -----------------------------------------
                // ================= O R ===================
                // -----------------------------------------
                for(int i_ms = 0; i_ms < i_limit.condition_groups_size(); ++i_ms)
                {
                        //NDBG_PRINT("limit[%d]: limit[%d] process\n", i_t, i_r);
                        const waflz_pb::condition_group &l_cg = i_limit.condition_groups(i_ms);
                        bool l_matched = false;
                        int32_t l_s;
                        l_s = process_condition_group(l_matched,
                                        l_cg,
                                                      a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(l_matched == false)
                        {
                                // no match -continue
                                continue;
                        }
                        //NDBG_PRINT("limit[%d]: limit[%d] MATCHED\n", i_t, i_r);
                        // ---------------------------------
                        // ************MATCH****************
                        // ---------------------------------
                        l_s = handle_match(ao_cfg,
                                           m_pb->customer_id(),
                                           i_limit,
                                           &l_cg,
                                           a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO log error reason
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(*ao_cfg)
                        {
                                return WAFLZ_STATUS_OK;
                        }
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details get a string key based on dimension values in connection
//!          (excludes time bucket)
//!          ASSUMES that gl_time has been updated already
//! @return  0 on success
//!          -1 on error
//! @param   a_key         The object to populate with the db key.
//! @param   a_connection  The object to pull values from to identify the key
//! ----------------------------------------------------------------------------
int32_t config::get_limit_key_value(char *ao_key,
                                   const std::string &a_cust_id,
                                   const waflz_pb::limit& a_limit,
                                   rqst_ctx *a_ctx)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        uint64_t l_dim_hash = 0;
        // -------------------------------------------------
        // for each key...
        // -------------------------------------------------
        for(int i_k = 0; i_k < a_limit.keys_size(); ++i_k)
        {
                waflz_pb::limit_key_t l_k = a_limit.keys(i_k);
                switch(l_k)
                {
                // -----------------------------------------
                // IP
                // -----------------------------------------
                case waflz_pb::limit_key_t_IP:
                {
                        const data_t &l_d = a_ctx->m_src_addr;
                        if(l_d.m_data &&
                           l_d.m_len)
                        {
                                l_dim_hash += CityHash64(l_d.m_data, l_d.m_len);
                        }
                        break;
                }
                // -----------------------------------------
                // USER_AGENT
                // -----------------------------------------
                case waflz_pb::limit_key_t_USER_AGENT:
                {
                        data_t l_d;
                        data_t l_v;
                        _GET_HEADER("User-Agent");
                        if(l_v.m_data &&
                           l_v.m_len)
                        {
                                l_dim_hash += CityHash64(l_v.m_data, l_v.m_len);
                        }
                        break;
                }
                // -----------------------------------------
                // ???
                // -----------------------------------------
                default:
                {
                        break;
                }
                }
        }
        // -------------------------------------------------
        // *************************************************
        //                K E Y   F O R M A T
        // *************************************************
        // -------------------------------------------------
        // SF:RL:<AN>:<LIMIT_ID>:
        // -------------------------------------------------
        if(a_limit.has__reserved_1() &&
           !a_limit._reserved_1().empty())
        {
                snprintf(ao_key, _MAX_KEY_LEN, "SF:RL:%s:%s:%" PRIX64 "", a_cust_id.c_str(), a_limit._reserved_1().c_str(), l_dim_hash);
        }
        else
        {
                snprintf(ao_key, _MAX_KEY_LEN, "SF:RL:%s:%s:%" PRIX64 "", a_cust_id.c_str(), a_limit.id().c_str(), l_dim_hash);
        }
        return WAFLZ_STATUS_OK;
}
}
