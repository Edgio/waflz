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
#include "support/ndebug.h"
#include "jspb/jspb.h"
#include "waflz/city.h"
#include "waflz/limit.h"
#include "waflz/kv_db.h"
#include "rapidjson/document.h"
#include "rapidjson/error/error.h"
#include "rapidjson/error/en.h"
#include "limit.pb.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
// the maximum size of the json defining configuration for a ddos enforcement (1MB)
#define _CONFIG_MAX_SIZE (1<<20)
#define _MAX_KEY_LEN 1024
//! ----------------------------------------------------------------------------
//! macros
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
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
limit::limit(kv_db &a_db,
             bool a_case_insensitive_headers):
        rl_obj(a_case_insensitive_headers),
        m_init(false),
        m_pb(NULL),
        m_db(a_db),
        m_id(),
        m_cust_id()
{
        m_pb = new waflz_pb::limit();
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
limit::~limit()
{
        if(m_pb) { delete m_pb; m_pb = NULL; }
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t limit::load(const char *a_buf, uint32_t a_buf_len)
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
int32_t limit::load(void *a_js)
{
        const rapidjson::Value &l_js = *((rapidjson::Value *)a_js);
        // -------------------------------------------------
        // load pbuf
        // -------------------------------------------------
        int32_t l_s;
        l_s = update_from_json(*m_pb, l_js);
        if(l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // init...
        // -------------------------------------------------
        l_s = init();
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
const std::string& limit::get_last_modified_date()
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
int32_t limit::init()
{
        if(m_init)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // *************************************************
        //              V A L I D A T I O N
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // has id
        // -------------------------------------------------
        if(!m_pb->has_id() ||
            m_pb->id().empty())
        {
                WAFLZ_PERROR(m_err_msg, "missing id field or empty");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // has num
        // -------------------------------------------------
        if(!m_pb->has_num() ||
           (m_pb->num() <= 0))
        {
                WAFLZ_PERROR(m_err_msg, "limit missing num field or num is <= 0");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // has duration
        // -------------------------------------------------
        if(!m_pb->has_duration_sec())
        {
                WAFLZ_PERROR(m_err_msg, "limit missing duration field");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // set id and cust_id
        // -------------------------------------------------
        m_id = m_pb->id();
        m_cust_id = m_pb->customer_id();
        // ------------------------------------------------
        // always on???
        // ------------------------------------------------
        // TODO
        // -------------------------------------------------
        // *************************************************
        //                C O M P I L E
        // *************************************************
        // -------------------------------------------------
        int32_t l_s;
        l_s = compile_limit(*m_pb);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "compiling limit");
                return WAFLZ_STATUS_ERROR;
        }
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t limit::process(bool &ao_exceeds,
                       const waflz_pb::condition_group** ao_cg,
                       const std::string& a_scope_id,
                       rqst_ctx* a_ctx)
{
        // -------------------------------------------------
        // sanity check...
        // -------------------------------------------------
        if(!ao_cg)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_cg = NULL;
        // init to false
        ao_exceeds = false;
        // -------------------------------------------------
        // overall algorithm:
        //   ...
        //   If a limit match indicates entire limit matched
        //     Construct db key
        //     Increment key value in db
        //     If value above limits limit
        //       Record limit being exceeded
        //   If limit exceeded for customer
        //     synthesize into enforcement config
        //   ...
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
        waflz_pb::limit &i_limit = *m_pb;
        // -------------------------------------------------
        // disabled???
        // -------------------------------------------------
        if(i_limit.has_disabled() &&
           i_limit.disabled())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // match-less limits...
        // -------------------------------------------------
        if(i_limit.condition_groups_size() == 0)
        {
                // -----------------------------------------
                // ****************MATCH********************
                // -----------------------------------------
                // TODO log?
                //TRC_DEBUG("Matched enforcement limit completely!\n");
                int32_t l_s;
                l_s = incr_key(ao_exceeds, a_scope_id, a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log error reason
                        return WAFLZ_STATUS_ERROR;
                }
                if(ao_exceeds)
                {
                        return WAFLZ_STATUS_OK;
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // limits w/condition_groups
        // -------------------------------------------------
        // ===================== O R =======================
        // -------------------------------------------------
        for(int i_ms = 0; i_ms < i_limit.condition_groups_size(); ++i_ms)
        {
                //NDBG_PRINT("limit[%d]: limit[%d] process\n", i_t, i_r);
                const waflz_pb::condition_group &l_cg = i_limit.condition_groups(i_ms);
                bool l_matched = false;
                int32_t l_s;
                l_s = process_condition_group(l_matched, l_cg, a_ctx);
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
                // -----------------------------------------
                // ****************MATCH********************
                // -----------------------------------------
                l_s = incr_key(ao_exceeds, a_scope_id, a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log error reason
                        return WAFLZ_STATUS_ERROR;
                }
                if(ao_exceeds)
                {
                        *ao_cg = &l_cg;
                        return WAFLZ_STATUS_OK;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t limit::incr_key(bool &ao_exceeds,
                        const std::string& a_scope_id,
                        rqst_ctx* a_ctx)
{
        // -------------------------------------------------
        // get key for limit
        // -------------------------------------------------
        // Construct db key eg:
        //   AN:LIMIT_ID:DIM1=DIM1VAL:...DIMN=DIMNVAL
        // -------------------------------------------------
        char l_key[_MAX_KEY_LEN];
        int32_t l_s;
        l_s = get_key(l_key, a_scope_id, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "Failed to generate db key for limit id: '%s'", m_pb->id().c_str());
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
                                 m_pb->duration_sec()*1000);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "Failed to perform db key increment for limit id: '%s' key: %s",
                             m_pb->id().c_str(),
                             l_key);
                return WAFLZ_STATUS_ERROR;
        }
        //NDBG_PRINT("KEY: %s VAL: %li\n", l_key, l_cur_num);
        // TODO log?
        //TRACE("Incremented time bucket key '%s' count to: %" PRIi64, bucket_key.b_str(), l_current_number);
        // -------------------------------------------------
        // limit is exceeding???
        // -------------------------------------------------
        if(l_cur_num > (int64_t)(m_pb->num()))
        {
                ao_exceeds = true;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t limit::get_key(char* ao_key,
                       const std::string& a_scope_id,
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
        for(int i_k = 0; i_k < m_pb->keys_size(); ++i_k)
        {
                waflz_pb::limit_key_t l_k = m_pb->keys(i_k);
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
        // SF:RL:<CUSTOMER_ID>:<SCOPE_ID>::<LIMIT_ID>:
        // -------------------------------------------------
        if(m_pb->has__reserved_1() &&
           !m_pb->_reserved_1().empty())
        {
                snprintf(ao_key, _MAX_KEY_LEN, "SF:RL:%s:%s:%s:%" PRIX64 "", m_pb->customer_id().c_str(), a_scope_id.c_str(), m_pb->_reserved_1().c_str(), l_dim_hash);
        }
        else
        {
                snprintf(ao_key, _MAX_KEY_LEN, "SF:RL:%s:%s:%s:%" PRIX64 "", m_pb->customer_id().c_str(), a_scope_id.c_str(), m_pb->id().c_str(), l_dim_hash);
        }
        return WAFLZ_STATUS_OK;
}

}
