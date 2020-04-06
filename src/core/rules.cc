//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    profile.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    04/15/2016
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
#include "waflz/rules.h"
#include "support/ndebug.h"
#include "waflz/engine.h"
#include "waflz/rqst_ctx.h"
#include "waflz/waf.h"
#include "event.pb.h"
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define _CONFIG_PROFILE_MAX_SIZE (1<<20)
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define VERIFY_HAS(_pb, _field) do { \
        if(!_pb.has_##_field()) { \
                WAFLZ_PERROR(m_err_msg, "missing %s field", #_field); \
                return WAFLZ_STATUS_ERROR; \
        } \
} while(0)
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
rules::rules(engine &a_engine):
        m_init(false),
        m_err_msg(),
        m_engine(a_engine),
        m_waf(NULL),
        m_id(),
        m_name()
{
}
//: ----------------------------------------------------------------------------
//: \details dtor
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
rules::~rules()
{
        if(m_waf) { delete m_waf; m_waf = NULL; }
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t rules::load_file(const char *a_buf, uint32_t a_buf_len)
{
        if(a_buf_len > _CONFIG_PROFILE_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                             a_buf_len,
                             _CONFIG_PROFILE_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        // -----------------------------------------
        // make waf obj
        // -----------------------------------------
        if(m_waf) { delete m_waf; m_waf = NULL; }
        m_waf = new waf(m_engine);
        std::string l_p;
        l_p.assign(a_buf, a_buf_len);
        int32_t l_s;
        l_s = m_waf->init(config_parser::JSON, l_p, true);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_AERROR(m_err_msg, "error loading conf file-reason: %s",
                             m_waf->get_err_msg());
                if(m_waf) { delete m_waf; m_waf = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -----------------------------------------
        // set version...
        // -----------------------------------------
        m_waf->set_owasp_ruleset_version(300);
        // -----------------------------------------
        // done...
        // -----------------------------------------
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t rules::process(waflz_pb::event **ao_event,
                       void *a_ctx,
                       rqst_ctx **ao_rqst_ctx)
{
        if(!ao_event)
        {
                WAFLZ_PERROR(m_err_msg, "ao_event == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        *ao_event = NULL;
        int32_t l_s;
        // -------------------------------------------------
        // create new if null
        // -------------------------------------------------
        rqst_ctx *l_rqst_ctx = NULL;
        if(ao_rqst_ctx &&
           *ao_rqst_ctx)
        {
                l_rqst_ctx = *ao_rqst_ctx;
        }
        if(!l_rqst_ctx)
        {
                uint32_t l_body_size_max = DEFAULT_BODY_SIZE_MAX;
                if(m_waf->get_request_body_in_memory_limit() > 0)
                {
                        l_body_size_max = m_waf->get_request_body_in_memory_limit();
                }
                l_rqst_ctx = new rqst_ctx(a_ctx,
                                          l_body_size_max,
                                          m_waf->get_parse_xml(),
                                          m_waf->get_parse_json());
                if(ao_rqst_ctx)
                {
                        *ao_rqst_ctx = l_rqst_ctx;
                }
        }
        // -------------------------------------------------
        // run phase 1 init
        // -------------------------------------------------
        l_s = l_rqst_ctx->init_phase_1(m_engine.get_geoip2_mmdb(), NULL, NULL, NULL);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::init_phase_1");
                if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        waflz_pb::event *l_event = NULL;
        // -------------------------------------------------
        // process waf...
        // -------------------------------------------------
        l_s = m_waf->process(&l_event, a_ctx, &l_rqst_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", m_waf->get_err_msg());
                if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        if(l_event)
        {
                // DS: todo check if browser challenge
                l_s = l_rqst_ctx->append_rqst_info(*l_event);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::append_rqst_info");
                        if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                l_event->set_rule_intercept_status(403);
                l_event->set_waf_profile_id(m_id);
                l_event->set_waf_profile_name(m_name);
                *ao_event = l_event;
        }
        if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        return WAFLZ_STATUS_OK;
}
}
