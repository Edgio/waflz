//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    scopes.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    06/06/2019
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
#include "waflz/scopes.h"
#include "waflz/rqst_ctx.h"
#include "waflz/config_parser.h"
#include "waflz/waf.h"
#include "support/ndebug.h"
#include "limit/rl_op.h"
#include "scope.pb.h"
#include "jspb/jspb.h"
#include "event.pb.h"
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define _SCOPES_MAX_SIZE (1024*1024)
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
//: Class Variables
//: ----------------------------------------------------------------------------
std::string scopes::s_conf_dir("/oc/local/waf/conf");
//: ----------------------------------------------------------------------------
//: \details ctor
//: \return  None
//: \param   TODO
//: ----------------------------------------------------------------------------
scopes::scopes(engine &a_engine,
               geoip2_mmdb &a_geoip2_mmdb):
        m_init(false),
        m_pb(NULL),
        m_err_msg(),
        m_engine(a_engine),
        m_geoip2_mmdb(a_geoip2_mmdb),
        m_id_rules_map()
{
        m_pb = new waflz_pb::scope_config();
}
//: ----------------------------------------------------------------------------
//: \brief   dtor
//: \deatils
//: \return  None
//: ----------------------------------------------------------------------------
scopes::~scopes()
{
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        // TODO clear parts...
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  0/-1
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes::validate(void)
{
        if(m_init)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // TODO -add validation...
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes::load_config(const char *a_buf,
                            uint32_t a_buf_len)
{
        if(a_buf_len > _SCOPES_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                             a_buf_len,
                             _SCOPES_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        // -------------------------------------------------
        // load from js object
        // -------------------------------------------------
        int32_t l_s;
        l_s = update_from_json(*m_pb, a_buf, a_buf_len);
        //TRC_DEBUG("whole config %s", m_pb->DebugString().c_str());
        if(l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate
        // -------------------------------------------------
        l_s = validate();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // for each scope...
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                l_s = load_parts(l_sc);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes::load_config(void *a_js)
{
        m_init = false;
        // -------------------------------------------------
        // load from js object
        // -------------------------------------------------
        const rapidjson::Document &l_js = *((rapidjson::Document *)a_js);
        int32_t l_s;
        l_s = update_from_json(*m_pb, l_js);
        if(l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate
        // -------------------------------------------------
        l_s = validate();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // for each scope...
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                l_s = load_parts(l_sc);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes::load_parts(waflz_pb::scope& a_scope)
{
        // -------------------------------------------------
        // acl audit
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // acl prod
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // rules audit
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // rules prod
        // -------------------------------------------------
        if(a_scope.has_rules_prod_id())
        {
                std::string l_p = s_conf_dir + "/rules/" + a_scope.rules_prod_id();
                // -----------------------------------------
                // make waf obj
                // -----------------------------------------
                waf* l_waf = new waf(m_engine);
                int32_t l_s;
                l_s = l_waf->init(config_parser::JSON, l_p, true);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading conf file: %s. reason: %s\n",
                                        l_p.c_str(),
                                   "__na__");
                                   // TODO -get reason...
                                   //l_wafl->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // set version...
                // -----------------------------------------
                l_waf->set_owasp_ruleset_version(300);
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__rules_prod__reserved((uint64_t)l_waf);
                m_id_rules_map[a_scope.rules_prod_id()] = l_waf;
        }
        // -------------------------------------------------
        // profile audit
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // profile prod
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // limits
        // -------------------------------------------------
        // TODO
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes::process(const waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        rqst_ctx **ao_rqst_ctx)
{
        if(!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s;
        // -------------------------------------------------
        // create rqst_ctx
        // -------------------------------------------------
        rqst_ctx *l_ctx = NULL;
        // TODO -fix args!!!
        //l_rqst_ctx = new rqst_ctx(a_ctx, l_body_size_max, m_waf->get_parse_json());
        l_ctx = new rqst_ctx(a_ctx, 1024, true);
        if(ao_rqst_ctx)
        {
                *ao_rqst_ctx = l_ctx;
        }
        // -------------------------------------------------
        // run phase 1 init
        // -------------------------------------------------
        l_s = l_ctx->init_phase_1(NULL, NULL, NULL);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if(!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // for each scope...
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                const ::waflz_pb::scope& l_sc = m_pb->scopes(i_s);
                bool l_m;
                l_s = in_scope(l_m, l_sc, l_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO -log error???
                        if(!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_m)
                {
                        // TODO process scope...
                        l_s = process(ao_enf, ao_audit_event, ao_prod_event, l_sc, a_ctx, ao_rqst_ctx);
                        goto done;
                }
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
done:
        if(!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes::process(const waflz_pb::enforcement** ao_enf,
                        waflz_pb::event** ao_audit_event,
                        waflz_pb::event** ao_prod_event,
                        const ::waflz_pb::scope& a_scope,
                        void *a_ctx,
                        rqst_ctx **ao_rqst_ctx)
{
        // TODO clear ao_* inputs
        *ao_enf = NULL;
        *ao_audit_event = NULL;
        *ao_prod_event = NULL;
        // -------------------------------------------------
        // *************************************************
        //                  A U D I T
        // *************************************************
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // *************************************************
        //                   P R O D
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // acl
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // rules
        // -------------------------------------------------
        if(a_scope.has__rules_prod__reserved())
        {
                // -----------------------------------------
                // process
                // -----------------------------------------
                waf *l_waf = (waf *)a_scope._rules_prod__reserved();
                waflz_pb::event *l_event = NULL;
                int32_t l_s;
                l_s = l_waf->process(&l_event, a_ctx, ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_event) { delete l_event; l_event = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_event)
                {
                        goto prod_profile;
                }
                *ao_prod_event = l_event;
                if(a_scope.has_rules_prod_action())
                {
                        *ao_enf = &(a_scope.rules_prod_action());
                }
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
        // TODO
prod_profile:
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;

}
}
