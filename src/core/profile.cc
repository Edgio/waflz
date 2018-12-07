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
#include "config.pb.h"
#include "enforcement.pb.h"
#include "request_info.pb.h"
#include "acl.pb.h"
#include "event.pb.h"
#include "jspb/jspb.h"
#include "support/ndebug.h"
#include "support/trace_internal.h"
#include "support/file_util.h"
#include "support/string_util.h"
#include "support/time_util.h"
#include "waflz/engine.h"
#include "op/regex.h"
#include "op/nms.h"
#include "cityhash/city.h"
#include "waflz/def.h"
#include "waflz/profile.h"
#include "waflz/acl.h"
#include "waflz/waf.h"
#include "waflz/rqst_ctx.h"
#include "waflz/config_parser.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define CONFIG_SECURITY_WAF_PROFILE_MAX_SIZE (1<<20)
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
// in an unreserved block
uint_fast32_t profile::s_next_ec_rule_id = 430000;
const std::string profile::s_default_name("");
std::string profile::s_ruleset_dir("/oc/local/waf/ruleset/");
std::string profile::s_geoip_db;
std::string profile::s_geoip_isp_db;
std::string profile::s_geoip2_db;
std::string profile::s_geoip2_isp_db;
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
profile::profile(engine &a_engine,
                 geoip2_mmdb &a_geoip2_mmdb):
        m_init(false),
        m_pb(NULL),
        m_err_msg(),
        m_engine(a_engine),
        m_geoip2_mmdb(a_geoip2_mmdb),
        m_acl(NULL),
        m_waf(NULL),
        m_id(),
        m_name(profile::s_default_name),
        m_resp_header_name(),
        m_action(waflz_pb::enforcement_type_t_NOP),
        m_leave_compiled_file(false),
        m_owasp_ruleset_version(229),
        m_paranoia_level(1),
        m_il_query(),
        m_il_header(),
        m_il_cookie()
{
        m_pb = new waflz_pb::profile();
        m_acl = new acl(a_geoip2_mmdb);
}
//: ----------------------------------------------------------------------------
//: \details dtor
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
profile::~profile()
{
        if(m_pb) { delete m_pb; m_pb = NULL; }
        if(m_acl) { delete m_acl; m_acl = NULL; }
        if(m_waf) { delete m_waf; m_waf = NULL; }
        clear_ignore_list(m_il_query);
        clear_ignore_list(m_il_header);
        clear_ignore_list(m_il_cookie);
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
void profile::set_pb(waflz_pb::profile *a_pb)
{
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        m_pb = a_pb;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t profile::load_config(const char *a_buf,
                             uint32_t a_buf_len,
                             bool a_leave_compiled_file)
{
        if(a_buf_len > CONFIG_SECURITY_WAF_PROFILE_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                             a_buf_len,
                             CONFIG_SECURITY_WAF_PROFILE_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        m_leave_compiled_file = a_leave_compiled_file;
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        if(m_acl)
        {
                delete m_acl;
                m_acl = NULL;
        }
        m_acl = new acl(m_geoip2_mmdb);
        // -------------------------------------------------
        // load from json
        // -------------------------------------------------
        m_pb = new waflz_pb::profile();
        int32_t l_s;
        l_s = update_from_json(*m_pb, a_buf, a_buf_len);
        //NDBG_PRINT("whole config %s", m_pb->DebugString().c_str());
        if(l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. reason: %s", get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = init();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t profile::load_config(const waflz_pb::profile *a_pb,
                             bool a_leave_compiled_file)
{
        if(!a_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL (input)");
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        m_leave_compiled_file = a_leave_compiled_file;
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        // -------------------------------------------------
        // copy from profile pb
        // -------------------------------------------------
        m_pb = new waflz_pb::profile();
        m_pb->CopyFrom(*a_pb);
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        int32_t l_s;
        l_s = init();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
void set_acl_wl_bl(::waflz_pb::acl_lists_t *ao_list,
                   const waflz_pb::profile_access_settings_t_lists_t &a_list)
{
        for(int32_t i_t = 0; i_t < a_list.whitelist_size(); ++i_t)
        {
                ao_list->add_whitelist(a_list.whitelist(i_t));
        }
        for(int32_t i_t = 0; i_t < a_list.blacklist_size(); ++i_t)
        {
                ao_list->add_blacklist(a_list.blacklist(i_t));
        }
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t profile::regex_list_add(const std::string &a_regex,
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
int32_t profile::init(void)
{
        if(m_init)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // validate/compile/load
        // -------------------------------------------------
        int32_t l_s;
        l_s = validate();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create new waf object...
        // -------------------------------------------------
        if(m_waf)
        {
                delete m_waf;
                m_waf = NULL;
        }
        m_waf = new waf(m_engine);
        // -------------------------------------------------
        // copy over properties
        // -------------------------------------------------
        m_waf->set_id(m_id);
        m_waf->set_name(m_name);
        m_waf->set_owasp_ruleset_version(m_owasp_ruleset_version);
        m_waf->set_paranoia_level(m_paranoia_level);
        // Json parser
        if(m_pb->general_settings().has_json_parser())
        {
                m_waf->set_parse_json(m_pb->general_settings().json_parser());
        }
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = m_waf->init(*this, m_leave_compiled_file);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "waf init reason: %s", m_waf->get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // *************************************************
        //                  I G N O R E
        // *************************************************
        // -------------------------------------------------
        const ::waflz_pb::profile_access_settings_t& l_as = m_pb->access_settings();
        // -------------------------------------------------
        // ignore query args
        // -------------------------------------------------
        if(l_as.ignore_query_args_size())
        {
                for(int32_t i_q = 0;
                    i_q < l_as.ignore_query_args_size();
                    ++i_q)
                {
                        std::string l_query_arg = l_as.ignore_query_args(i_q);
                        l_s = regex_list_add(l_query_arg, m_il_query);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        // -------------------------------------------------
        // ignore headers
        // -------------------------------------------------
        if(l_as.ignore_header_size())
        {
                for(int32_t i_h = 0;
                    i_h < l_as.ignore_header_size();
                    ++i_h)
                {
                        std::string l_header = l_as.ignore_header(i_h);
                        l_s = regex_list_add(l_header, m_il_header);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        // -------------------------------------------------
        // ignore cookies
        // -------------------------------------------------
        if(l_as.ignore_cookie_size())
        {
                for(int32_t i_c = 0;
                    i_c < l_as.ignore_cookie_size();
                    ++i_c)
                {
                        std::string l_cookie = l_as.ignore_cookie(i_c);
                        l_s = regex_list_add(l_cookie, m_il_cookie);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        // -------------------------------------------------
        // *************************************************
        //                     A C L
        // *************************************************
        // -------------------------------------------------
        const ::waflz_pb::profile &l_pb = *m_pb;
        if(!l_pb.has_access_settings())
        {
                WAFLZ_PERROR(m_err_msg, "pb missing access settings");
                return WAFLZ_STATUS_ERROR;
        }
        // Get acl proto so that we copy over from profile
        ::waflz_pb::acl *l_acl_pb = m_acl->get_pb();
        // TODO: Remove copy once we switch to acl json
        // **************************************************
        //              access settings
        // **************************************************
        if(l_as.has_country())
        {
                ::waflz_pb::acl_lists_t* l_c =  l_acl_pb->mutable_country();
                set_acl_wl_bl(l_c, l_as.country());
        }
        if(l_as.has_ip())
        {
                ::waflz_pb::acl_lists_t* l_ip =  l_acl_pb->mutable_ip();
                set_acl_wl_bl(l_ip, l_as.ip());
        }
        if(l_as.has_referer())
        {
                ::waflz_pb::acl_lists_t* l_url =  l_acl_pb->mutable_referer();
                set_acl_wl_bl(l_url, l_as.referer());
        }
        if(l_as.has_url())
        {
                ::waflz_pb::acl_lists_t* l_url =  l_acl_pb->mutable_url();
                set_acl_wl_bl(l_url, l_as.url());
        }
        if(l_as.has_user_agent())
        {
                ::waflz_pb::acl_lists_t* l_ua =  l_acl_pb->mutable_user_agent();
                set_acl_wl_bl(l_ua, l_as.user_agent());
        }
        if(l_as.has_cookie())
        {
                ::waflz_pb::acl_lists_t* l_cki =  l_acl_pb->mutable_cookie();
                set_acl_wl_bl(l_cki, l_as.cookie());
        }
        if(l_as.has_asn())
        {
                ::waflz_pb::acl_lists_asn_t* l_asn =  l_acl_pb->mutable_asn();
                for(int32_t i_t = 0; i_t < l_as.asn().whitelist_size(); ++i_t)
                {
                        l_asn->add_whitelist(l_as.asn().whitelist(i_t));
                }
                for(int32_t i_t = 0; i_t < l_as.asn().blacklist_size(); ++i_t)
                {
                        l_asn->add_blacklist(l_as.asn().blacklist(i_t));
                }
        }
        // **************************************************
        //              general settings
        // **************************************************
        const ::waflz_pb::profile_general_settings_t& l_gs = m_pb->general_settings();
#define _SET_ACL(_field) \
for(int32_t i_t = 0; i_t < l_gs._field##_size(); ++i_t) { \
l_acl_pb->add_##_field(l_gs._field(i_t)); \
}
        if(l_gs.allowed_http_methods_size())
        {
                _SET_ACL(allowed_http_methods);
        }
        if(l_gs.allowed_http_versions_size())
        {
                _SET_ACL(allowed_http_versions);
        }
        if(l_gs.allowed_request_content_types_size())
        {
                _SET_ACL(allowed_request_content_types);
        }
        if(l_gs.disallowed_extensions_size())
        {
                _SET_ACL(disallowed_extensions);
        }
        if(l_gs.disallowed_headers_size())
        {
                _SET_ACL(disallowed_headers);
        }
        if(l_gs.has_max_file_size())
        {
                l_acl_pb->set_max_file_size(l_gs.max_file_size());
        }
        l_s = m_acl->compile();
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "access settings: reason: %s", m_acl->get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details Validate json for generating modsecurity configuration
//:          For now we do this simply by checking that it has all
//:          the required elements.  We could use a json-schema
//:          implementation in C (http://json-schema.org/implementations.html)
//:          but we have such a nice lightweight json component, it seems
//:          a shame to bring in a huge thing just for this use
//: \return  0 if it is valid, ao_err_msg reset
//:          -1 if it is not and ao_err_msg is populated
//: ----------------------------------------------------------------------------
int32_t profile::validate(void)
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
        const waflz_pb::profile &l_pb = *m_pb;
        // -------------------------------------------------
        // id/name
        // -------------------------------------------------
        VERIFY_HAS(l_pb, id);
        VERIFY_HAS(l_pb, name);
        // -------------------------------------------------
        // ruleset info
        // -------------------------------------------------
        VERIFY_HAS(l_pb, ruleset_id);
        VERIFY_HAS(l_pb, ruleset_version);
        // -------------------------------------------------
        // OWASP version detection hack
        // -used for anomaly variable naming
        // OWASP-CRS 3.0.0 + or ECRS
        // TODO not robust!!!
        // -------------------------------------------------
        if(l_pb.has_ruleset_id() &&
           ((l_pb.ruleset_id() == "ECRS")||
            (l_pb.ruleset_id().find("OWASP-CRS-3.") != std::string::npos)))
        {
                m_owasp_ruleset_version = 300;
        }
        m_id = m_pb->id();
        m_name = m_pb->name();
        // -------------------------------------------------
        // general settings
        // -------------------------------------------------
        VERIFY_HAS(l_pb, general_settings);
        const ::waflz_pb::profile_general_settings_t& l_gs = l_pb.general_settings();
        // set paranoia
        if(l_gs.has_paranoia_level())
        {
                m_paranoia_level = l_gs.paranoia_level();
        }
        VERIFY_HAS(l_gs, xml_parser);
        VERIFY_HAS(l_gs, validate_utf8_encoding);
        VERIFY_HAS(l_gs, max_num_args);
        VERIFY_HAS(l_gs, arg_name_length);
        VERIFY_HAS(l_gs, arg_length);
        VERIFY_HAS(l_gs, total_arg_length);
        VERIFY_HAS(l_gs, max_file_size);
        VERIFY_HAS(l_gs, combined_file_sizes);
        // set...
        if(l_gs.has_response_header_name())
        {
                m_resp_header_name = l_gs.response_header_name();
        }
        // -------------------------------------------------
        // access settings
        // -------------------------------------------------
        VERIFY_HAS(l_pb, access_settings);
        const ::waflz_pb::profile_access_settings_t& l_as = l_pb.access_settings();
        VERIFY_HAS(l_as, country);
        VERIFY_HAS(l_as, ip);
        VERIFY_HAS(l_as, url);
        VERIFY_HAS(l_as, referer);
        // -------------------------------------------------
        // anomaly settings
        // -------------------------------------------------
        VERIFY_HAS(l_gs, anomaly_settings);
        const ::waflz_pb::profile_general_settings_t_anomaly_settings_t& l_ax = l_gs.anomaly_settings();
        VERIFY_HAS(l_ax, critical_score);
        VERIFY_HAS(l_ax, error_score);
        VERIFY_HAS(l_ax, warning_score);
        VERIFY_HAS(l_ax, notice_score);
        VERIFY_HAS(l_ax, inbound_threshold);
        VERIFY_HAS(l_ax, outbound_threshold);
        // -------------------------------------------------
        // disabled rules
        // -------------------------------------------------
        if(l_pb.disabled_rules_size())
        {
                for(int32_t i_r = 0;
                    i_r < l_pb.disabled_rules_size();
                    ++i_r)
                {
                        const waflz_pb::profile_disabled_rule_t& l_r = l_pb.disabled_rules(i_r);
                        VERIFY_HAS(l_r, rule_id);
                }
        }
        // -------------------------------------------------
        // custom rules
        // -------------------------------------------------
        // TODO ???
        // -------------------------------------------------
        // rule target updates --optional
        // -------------------------------------------------
        if(l_pb.rule_target_updates_size())
        {
                for(int32_t i_r = 0;
                    i_r < l_pb.rule_target_updates_size();
                    ++i_r)
                {
                        const waflz_pb::profile_rule_target_update_t& l_r = l_pb.rule_target_updates(i_r);
                        VERIFY_HAS(l_r, rule_id);
                        VERIFY_HAS(l_r, target);
                        VERIFY_HAS(l_r, target_match);
                        VERIFY_HAS(l_r, is_regex);
                }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t profile::process(waflz_pb::event **ao_event,
                         void *a_ctx,
                         rqst_ctx **ao_rqst_ctx)
{
        if(!ao_event)
        {
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
                l_rqst_ctx = new rqst_ctx(a_ctx, l_body_size_max, m_waf->get_parse_json());
                if(ao_rqst_ctx)
                {
                        *ao_rqst_ctx = l_rqst_ctx;
                }
        }
        // run phase 1 init
        // -------------------------------------------------
        l_s = l_rqst_ctx->init_phase_1(&m_il_query, &m_il_header, &m_il_cookie);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // acl
        // -------------------------------------------------
        bool l_whitelist = false;
        waflz_pb::event *l_event = NULL;
        l_s = m_acl->process(&l_event, l_whitelist, a_ctx, &l_rqst_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO log error reason???
                if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if in whitelist -bail out of modsec processing
        // -------------------------------------------------
        if(l_whitelist)
        {
                if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                return WAFLZ_STATUS_OK;
        }
        else if(l_event)
        {
                goto done;
        }
        // -------------------------------------------------
        // process waf...
        // -------------------------------------------------
        l_s = m_waf->process(&l_event, a_ctx, &l_rqst_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO log error reason???
                if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
done:
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        if(l_event)
        {
                l_s = l_rqst_ctx->append_rqst_info(*l_event);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log error reason???
                        if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                l_event->set_rule_intercept_status(403);
                l_event->set_waf_profile_id(m_pb->id());
                l_event->set_waf_profile_name(m_pb->name());
                *ao_event = l_event;
        }
        if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        return WAFLZ_STATUS_OK;
}
}
