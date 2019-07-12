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
#include "waflz/engine.h"
#include "waflz/limit/rl_obj.h"
#include "support/ndebug.h"
#include "support/base64.h"
#include "op/nms.h"
#include "op/regex.h"
#include "scope.pb.h"
#include "jspb/jspb.h"
#include "event.pb.h"
#include <fnmatch.h>
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
//: utils
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t compile_action(waflz_pb::enforcement& ao_axn, char* ao_err_msg)
{
        // -------------------------------------------------
        // convert type string to enf_type
        // -------------------------------------------------
        if(!ao_axn.has_enf_type() &&
            ao_axn.has_type())
        {
                const std::string &l_type = ao_axn.type();
#define _ELIF_TYPE(_str, _type) else \
if(strncasecmp(l_type.c_str(), _str, sizeof(_str)) == 0) { \
        ao_axn.set_enf_type(waflz_pb::enforcement_type_t_##_type); \
}
            if(0) {}
            _ELIF_TYPE("REDIRECT_302", REDIRECT_302)
            _ELIF_TYPE("REDIRECT-302", REDIRECT_302)
            _ELIF_TYPE("REDIRECT_JS", REDIRECT_JS)
            _ELIF_TYPE("REDIRECT-JS", REDIRECT_JS)
            _ELIF_TYPE("HASHCASH", HASHCASH)
            _ELIF_TYPE("CUSTOM_RESPONSE", CUSTOM_RESPONSE)
            _ELIF_TYPE("CUSTOM-RESPONSE", CUSTOM_RESPONSE)
            _ELIF_TYPE("DROP_REQUEST", DROP_REQUEST)
            _ELIF_TYPE("DROP-REQUEST", DROP_REQUEST)
            _ELIF_TYPE("DROP_CONNECTION", DROP_CONNECTION)
            _ELIF_TYPE("DROP-CONNECTION", DROP_CONNECTION)
            _ELIF_TYPE("NOP", NOP)
            _ELIF_TYPE("ALERT", ALERT)
            _ELIF_TYPE("BLOCK_REQUEST", BLOCK_REQUEST)
            _ELIF_TYPE("BLOCK-REQUEST", BLOCK_REQUEST)
            _ELIF_TYPE("BROWSER_CHALLENGE", BROWSER_CHALLENGE)
            _ELIF_TYPE("BROWSER-CHALLENGE", BROWSER_CHALLENGE)
            else
            {
                    WAFLZ_PERROR(ao_err_msg, "unrecognized enforcement type string: %s", l_type.c_str());
                    return WAFLZ_STATUS_ERROR;
            }
        }
        // -------------------------------------------------
        // convert b64 encoded resp
        // -------------------------------------------------
        if(!ao_axn.has_response_body() &&
                        ao_axn.has_response_body_base64() &&
           !ao_axn.response_body_base64().empty())
        {
                const std::string& l_b64 = ao_axn.response_body_base64();
                char* l_body = NULL;
                size_t l_body_len = 0;
                int32_t l_s;
                l_s = b64_decode(&l_body, l_body_len, l_b64.c_str(), l_b64.length());
                if(!l_body ||
                   !l_body_len ||
                   (l_s != WAFLZ_STATUS_OK))
                {
                        WAFLZ_PERROR(ao_err_msg, "decoding response_body_base64 string: %s", l_b64.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                ao_axn.mutable_response_body()->assign(l_body, l_body_len);
                if(l_body) { free(l_body); l_body = NULL; }
        }
        return WAFLZ_STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: Class Variables
//: ----------------------------------------------------------------------------
std::string scopes::s_conf_dir("/oc/local/waf/conf");
//: ----------------------------------------------------------------------------
//: \details ctor
//: \return  None
//: \param   TODO
//: ----------------------------------------------------------------------------
scopes::scopes(engine &a_engine):
        m_init(false),
        m_pb(NULL),
        m_err_msg(),
        m_engine(a_engine),
        m_id(),
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
        m_id= m_pb->id();
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
        // rules prod action
        // -------------------------------------------------
        if(a_scope.has_rules_prod_action())
        {
                waflz_pb::enforcement *l_a = a_scope.mutable_rules_prod_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
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
        NDBG_PRINT("%s\n", a_scope.DebugString().c_str());
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
        l_s = l_ctx->init_phase_1(m_engine.get_geoip2_mmdb(), NULL, NULL, NULL);
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
//: ----------------------------------------------------------------------------
//: \details  run a limit operator on some data
//: \l_retval number of entries added to ao_match_list
//:           -1 on failure
//: \param    TODO
//: ----------------------------------------------------------------------------
int32_t rl_run_op(bool &ao_matched,
                  const waflz_pb::op_t &a_op,
                  const char *a_data,
                  uint32_t a_len,
                  bool a_case_insensitive)
{
        // assume operator is STREQ
        ao_matched = false;
        waflz_pb::op_t_type_t l_op_type = waflz_pb::op_t_type_t_STREQ;
        if(a_op.has_type())
        {
                // operator type actually provided
                l_op_type = a_op.type();
        }
        switch (l_op_type)
        {
        // -------------------------------------------------
        // RX (regex)
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_RX:
        {
                // -----------------------------------------
                // get regex
                // -----------------------------------------
                if(!a_op.has__reserved_1())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                regex *l_rx = (regex *)(a_op._reserved_1());
                if(!l_rx)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // match?
                // -----------------------------------------
                //TRC_ALL("RX[%p]: %s == %.*s\n", l_rx, l_rx->get_regex_string().c_str(), (int)a_len, a_data);
                int l_s;
                l_s = l_rx->compare(a_data, a_len);
                // if failed to match
                if(l_s < 0)
                {
                        break;
                }
                ao_matched = true;
                break;
        }
        // -------------------------------------------------
        // STREQ
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_STREQ:
        {
                const std::string &l_op_match = a_op.value();
                uint32_t l_len = l_op_match.length();
                if(l_len != a_len)
                {
                        break;
                }
                int l_cmp = 0;
                if(a_case_insensitive)
                {
                        l_cmp = strncasecmp(l_op_match.c_str(), a_data, l_len);
                }
                else
                {
                        l_cmp = strncmp(l_op_match.c_str(), a_data, l_len);
                }
                if(l_cmp == 0)
                {
                        // matched
                        ao_matched = true;
                        break;
                }
                //TRACE("Got data: '%.*s' and match '%s'", SUBBUF_FORMAT(a_data), l_op_match.c_str());
                break;
        }
        // -------------------------------------------------
        // PM
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_PM:
        {
                // -----------------------------------------
                // substring match multiple strings
                // -----------------------------------------
                // most naive possible implementation
                // TODO explore using pm operator
                // -----------------------------------------
                for(int i_val = 0; i_val < a_op.values_size(); ++i_val)
                {
                        // for each value
                        const std::string& l_op_match = a_op.values(i_val);
                        if(l_op_match.length() > a_len)
                        {
                                continue;
                        }
                        // If match value empty, continue
                        if(l_op_match.empty())
                        {
                                continue;
                        }
                        const char *l_match = 0;
                        if(a_case_insensitive)
                        {
                                l_match = strcasestr(a_data, l_op_match.c_str());
                        }
                        else
                        {
                                l_match = strstr(a_data, l_op_match.c_str());
                        }
                        if(l_match != NULL)
                        {
                                // matched
                                ao_matched = true;
                                break;
                        }
                        //TRACE("Got data: '%.*s' and match[%u] '%s'", SUBBUF_FORMAT(a_data), i_val, l_op_match.c_str());
                }
                break;
        }
        // -------------------------------------------------
        // GLOB (glob -wildcard match)
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_GLOB:
        {
                int l_flags = FNM_NOESCAPE;
                if(a_case_insensitive)
                {
                        l_flags |= FNM_CASEFOLD;
                }
                int l_cmp;
                const std::string &l_op_match = a_op.value();
                l_cmp = fnmatch(l_op_match.c_str(), a_data, l_flags);
                if(l_cmp == 0)
                {
                        // matched
                        ao_matched = true;
                }
                break;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_IPMATCH:
        {
                // -----------------------------------------
                // get regex
                // -----------------------------------------
                if(!a_op.has__reserved_1())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                nms *l_nms = (nms *)(a_op._reserved_1());
                if(!l_nms)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // match?
                // -----------------------------------------
                int32_t l_s;
                l_s = l_nms->contains(ao_matched, a_data, a_len);
                // if failed to match
                if(l_s < 0)
                {
                        break;
                }
                break;
        }
        // -------------------------------------------------
        // Exact Match list (EM)
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_EM:
        {
                // -----------------------------------------
                // get str set
                // -----------------------------------------
                if(!a_op.has__reserved_1())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // case insensitive
                // -----------------------------------------
                if(a_op.is_case_insensitive())
                {
                        data_case_i_set_t *l_ds = (data_case_i_set_t *)(a_op._reserved_1());
                        if(!l_ds)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // match?
                        // ---------------------------------
                        data_t l_d;
                        l_d.m_data = a_data;
                        l_d.m_len = a_len;
                        data_set_t::const_iterator i_d = l_ds->find(l_d);
                        if((i_d != l_ds->end()) &&
                           (i_d->m_len == l_d.m_len))
                        {
                                ao_matched = true;
                        }
                }
                // -----------------------------------------
                // case sensitive
                // -----------------------------------------
                else
                {
                        data_set_t *l_ds = (data_set_t *)(a_op._reserved_1());
                        if(!l_ds)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // match?
                        // ---------------------------------
                        data_t l_d;
                        l_d.m_data = a_data;
                        l_d.m_len = a_len;
                        data_set_t::const_iterator i_d = l_ds->find(l_d);
                        if((i_d != l_ds->end()) &&
                           (i_d->m_len == l_d.m_len))
                        {
                                ao_matched = true;
                        }
                }
                break;
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
        if(a_op.is_negated())
        {
                // negate value
                ao_matched = !ao_matched;
        }
        // -------------------------------------------------
        // TODO -push matches???
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details check if request "in scope"
//: \return  true if in scope
//:          false if not in scope
//: \param   a_scope TODO
//: \param   a_ctx   TODO
//: ----------------------------------------------------------------------------
int32_t in_scope(bool &ao_match,
                 const waflz_pb::scope &a_scope,
                 rqst_ctx *a_ctx)
{
        ao_match = false;
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // host
        // -------------------------------------------------
        if(a_scope.has_host() &&
           a_scope.host().has_type() &&
           (a_scope.host().has_value() ||
            a_scope.host().values_size()))
        {
                const data_t &l_d = a_ctx->m_host;
                if(!l_d.m_data ||
                   !l_d.m_len)
                {
                        return WAFLZ_STATUS_OK;
                }
                bool l_matched = false;
                int32_t l_s;
                l_s = rl_run_op(l_matched,
                                a_scope.host(),
                                l_d.m_data,
                                l_d.m_len,
                                true);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_matched)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // path
        // -------------------------------------------------
        if(a_scope.has_path() &&
           a_scope.path().has_type() &&
           (a_scope.path().has_value() ||
            a_scope.path().values_size()))
        {
                data_t l_d = a_ctx->m_uri;
                if(!l_d.m_data ||
                   !l_d.m_len)
                {
                        return WAFLZ_STATUS_OK;
                }
                // use length w/o q string
                // use length w/o q string
                if(a_ctx->m_uri_path_len)
                {
                        l_d.m_len = a_ctx->m_uri_path_len;
                }
                bool l_matched = false;
                int32_t l_s;
                l_s = rl_run_op(l_matched,
                                a_scope.path(),
                                l_d.m_data,
                                l_d.m_len,
                                true);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_matched)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        ao_match = true;
        return WAFLZ_STATUS_OK;
}
}
