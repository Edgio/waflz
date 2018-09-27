//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    waf.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    02/16/2018
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
#include "rule.pb.h"
#include "event.pb.h"
#include "config.pb.h"
// ---------------------------------------------------------
// internal
// ---------------------------------------------------------
#include "waflz/def.h"
#include "waflz/waf.h"
#include "waflz/rqst_ctx.h"
#include "waflz/engine.h"
#include "waflz/profile.h"
#include "op/regex.h"
#include "op/ac.h"
#include "support/ndebug.h"
#include "support/file_util.h"
#include "support/string_util.h"
#include "support/md5_hasher.h"
#include "support/time_util.h"
#include "core/op.h"
#include "core/var.h"
#include "core/tx.h"
#include "core/macro.h"
#include "jspb/jspb.h"
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define DEL_LAST_CHAR(_str) _str.erase(_str.size() - 1)
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
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
waf::waf(engine &a_engine):
        // -------------------------------------------------
        // protobuf
        // -------------------------------------------------
        m_pb(NULL),
        // -------------------------------------------------
        // compiled
        // -------------------------------------------------
        m_compiled_config(NULL),
        m_ctype_parser_map(a_engine.get_ctype_parser_map()),
        m_mx_rule_list()
#ifdef WAFLZ_NATIVE_ANOMALY_MODE
        ,m_anomaly_score_cur(0),
#endif
        m_il_query(),
        m_il_header(),
        m_il_cookie(),
        m_is_initd(false),
        m_engine(a_engine),
        m_id("NA"),
        m_name("NA"),
        m_owasp_ruleset_version(0),
        m_no_log_matched(false),
        m_parse_json(false)
{
        m_compiled_config = new compiled_config_t();
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
waf::~waf()
{
        if(m_compiled_config) { delete m_compiled_config; m_compiled_config = NULL; }
        if(m_pb) { delete m_pb; m_pb = NULL; }
        for(directive_list_t::iterator i_d = m_mx_rule_list.begin();
            i_d != m_mx_rule_list.end();
            ++i_d)
        {
                if(!*i_d) { continue; }
                delete *i_d;
                *i_d = NULL;
        }
        clear_ignore_list(m_il_query);
        clear_ignore_list(m_il_header);
        clear_ignore_list(m_il_cookie);
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#if 0
void waf::show(void)
{
        std::string l_config = m_pb->DebugString();
        colorize_string(l_config);
        NDBG_OUTPUT("%s\n", l_config.c_str());
}
#endif
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#if 0
void waf::show_status(void)
{
        m_parser.show_status();
}
#endif
int32_t waf::regex_list_add(const std::string &a_regex,
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
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::get_str(std::string &ao_str, config_parser::format_t a_format)
{
        bool l_s;
        switch(a_format)
        {
        // ---------------------------------------
        // Protobuf
        // ---------------------------------------
        case config_parser::PROTOBUF:
        {
                l_s = m_pb->SerializeToString(&ao_str);
                if(!l_s)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                else
                {
                        return WAFLZ_STATUS_OK;
                }
                break;
        }
        // ---------------------------------------
        // json
        // ---------------------------------------
        case config_parser::JSON:
        {
                // convert protobuf message to JsonCpp object
                try
                {
                        ns_waflz::convert_to_json(ao_str, *m_pb);
                }
                catch(int e)
                {
                        NDBG_PRINT("Error -json_protobuf::convert_to_json threw\n");
                        return WAFLZ_STATUS_ERROR;
                }
                return WAFLZ_STATUS_OK;
        }
        // ---------------------------------------
        // modsecurity
        // ---------------------------------------
        case config_parser::MODSECURITY:
        {
                l_s = config_parser::get_modsec_config_str(ao_str, *m_pb);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        //NDBG_PRINT("Error performing get_modsec_config_str\n");
                        return WAFLZ_STATUS_ERROR;
                }
                else
                {
                        return WAFLZ_STATUS_OK;
                }
                break;
        }
        default:
        {
                NDBG_PRINT("Error -unrecognized format specification[%d]\n", a_format);
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: types for organizing rule modifications
//: ----------------------------------------------------------------------------
typedef std::map <waflz_pb::variable_t_type_t, waflz_pb::variable_t> _type_var_map_t;
typedef std::map <std::string, _type_var_map_t> _id_tv_map_t;
//: ----------------------------------------------------------------------------
//: \details: This function generates a modified rule based on RTUs.
//:           The RTUs are stored in id to variable map (a_tv_map).
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int32_t create_modified_rule(::waflz_pb::directive_t** ao_drx,
                                    regex_list_t &ao_rx_list,
                                    const _type_var_map_t& a_tv_map,
                                    const ::waflz_pb::sec_rule_t &a_rule,
                                    bool a_replace = false)
{
        if(!ao_drx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        ::waflz_pb::directive_t* l_drx = new waflz_pb::directive_t();
        ::waflz_pb::sec_rule_t *l_mx_r = l_drx->mutable_sec_rule();
        l_mx_r->CopyFrom(a_rule);
        // -------------------------------------------------
        // for each var...
        // -------------------------------------------------
        for(int32_t i_v = 0; i_v < l_mx_r->variable_size(); ++i_v)
        {
                ::waflz_pb::variable_t& l_v = *(l_mx_r->mutable_variable(i_v));
                if(!l_v.has_type())
                {
                        continue;
                }
                // -----------------------------------------
                // variable is type...
                // -----------------------------------------
                _type_var_map_t::const_iterator i_vm = a_tv_map.find(l_v.type());
                if(i_vm == a_tv_map.end())
                {
                        continue;
                }
                // -----------------------------------------
                // if replace -replace whole var
                // -----------------------------------------
                if(a_replace)
                {
                        l_v.CopyFrom(i_vm->second);
                        continue;
                }
                const ::waflz_pb::variable_t& l_vm = i_vm->second;
                // -----------------------------------------
                // update the variable match
                // -----------------------------------------
                for(int32_t i_m = 0; i_m < l_vm.match_size(); ++i_m)
                {
                        const ::waflz_pb::variable_t_match_t& l_mm = l_vm.match(i_m);
                        if(!l_mm.has_value())
                        {
                                continue;
                        }
                        ::waflz_pb::variable_t_match_t* l_new_mx = l_v.add_match();
                        l_new_mx->CopyFrom(l_mm);
                        // ---------------------------------
                        // regex...
                        // ---------------------------------
                        if(l_mm.is_regex())
                        {
                                regex *l_pcre = NULL;
                                l_pcre = new regex();
                                const std::string &l_rx = l_mm.value();
                                int32_t l_s;
                                l_s = l_pcre->init(l_rx.c_str(), l_rx.length());
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        // TODO -log error reason???
                                        return WAFLZ_STATUS_ERROR;
                                }
                                ao_rx_list.push_back(l_pcre);
                                l_new_mx->set__reserved_1((uint64_t)l_pcre);
                        }
                }
        }
        *ao_drx = l_drx;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: Modify the directives based on a_dr_id_set, ao_id_tv_map
//:           and ao_id_tv_replace_map. The modified rules are stored in
//:           ao_mx_directive_list (m_mx_rule_list) and the references to rules
//:           in _compiled_config are updated to refer these
//:           instead of the rules in global rulesets
//: \return:  TODO
//: \param:   ao_directive_list: list of all directives
//:           ao_mx_directive_list: list of all modified directives
//:           ao_rx_list: list of all compiled regex
//:           a_dr_id_set: ids of rule to be removed
//:           ao_id_tv_map: rule id to variable map, for updating target
//:           ao_id_tv_replace_map: rule id to varaible replace map
//: ----------------------------------------------------------------------------
static int32_t modify_directive_list(directive_list_t &ao_directive_list,
                                     directive_list_t &ao_mx_directive_list,
                                     regex_list_t &ao_rx_list,
                                     const disabled_rule_id_set_t &a_dr_id_set,
                                     const _id_tv_map_t &ao_id_tv_map,
                                     const _id_tv_map_t &ao_id_tv_replace_map)
{
        // -------------------------------------------------
        // find rules
        // -------------------------------------------------
        for(directive_list_t::iterator i_d = ao_directive_list.begin();
            i_d != ao_directive_list.end();)
        {
                if(!(*i_d))
                {
                        ++i_d;
                        continue;
                }
                const ::waflz_pb::directive_t& l_d = **i_d;
                if(!l_d.has_sec_rule() ||
                   !l_d.sec_rule().has_action() ||
                   !l_d.sec_rule().action().has_id())
                {
                        ++i_d;
                        continue;
                }
                const std::string& l_id = l_d.sec_rule().action().id();
                // -----------------------------------------
                // check for remove rule id
                // -----------------------------------------
                if((a_dr_id_set.find(l_id) != a_dr_id_set.end()))
                {
                        ao_directive_list.erase(i_d++);
                        continue;
                }
                _id_tv_map_t::const_iterator i_id;
                // -----------------------------------------
                // id in map (replace)
                // -----------------------------------------
                i_id = ao_id_tv_replace_map.find(l_id);
                if(i_id != ao_id_tv_replace_map.end())
                {
                        const _type_var_map_t& l_tv_map = i_id->second;
                        const ::waflz_pb::sec_rule_t& l_r = l_d.sec_rule();
                        // ---------------------------------
                        // check for modified
                        // ---------------------------------
                        bool l_is_modified = false;
                        for(int32_t i_v = 0; i_v < l_r.variable_size(); ++i_v)
                        {
                                const ::waflz_pb::variable_t& l_v = l_r.variable(i_v);
                                if(!l_v.has_type())
                                {
                                        continue;
                                }
                                if(l_tv_map.find(l_v.type()) != l_tv_map.end())
                                {
                                        l_is_modified = true;
                                        break;
                                }
                        }
                        // ---------------------------------
                        // if modified update rule
                        // ---------------------------------
                        if(l_is_modified)
                        {
                                ::waflz_pb::directive_t* l_drx = NULL;
                                int32_t l_s;
                                l_s = create_modified_rule(&l_drx, ao_rx_list, l_tv_map, l_r, true);
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        return WAFLZ_STATUS_ERROR;
                                }
                                ao_mx_directive_list.push_back(l_drx);
                                *i_d = l_drx;
                        }
                }
                // -----------------------------------------
                // id in map
                // -----------------------------------------
                i_id = ao_id_tv_map.find(l_id);
                if(i_id != ao_id_tv_map.end())
                {       int32_t l_cr_idx = -1;
                        const ::waflz_pb::sec_rule_t& l_r = l_d.sec_rule();
                        // check for chained rules as well.
                        do
                        {
                                const waflz_pb::sec_rule_t *l_rule = NULL;
                                if(l_cr_idx == -1)
                                {
                                        l_rule = &l_r;
                                }
                                if((l_cr_idx >= 0) &&
                                    (l_cr_idx < l_d.sec_rule().chained_rule_size()))
                                {
                                        l_rule = &(l_r.chained_rule(l_cr_idx));
                                }
                                const _type_var_map_t& l_tv_map = i_id->second;
                                // ---------------------------------
                                // check for modified
                                // ---------------------------------
                                bool l_is_modified = false;
                                for(int32_t i_v = 0; i_v < l_rule->variable_size(); ++i_v)
                                {
                                        const ::waflz_pb::variable_t& l_v = l_rule->variable(i_v);
                                        // ---------------------------------
                                        // variable type doesn't match
                                        // move on to next.
                                        // ---------------------------------
                                        if(!l_v.has_type())
                                        {
                                                continue;
                                        }
                                        if(l_tv_map.find(l_v.type()) != l_tv_map.end())
                                        {
                                                l_is_modified = true;
                                                break;
                                        }
                                }
                                // ---------------------------------
                                // if modified update rule
                                // ---------------------------------
                                if(l_is_modified)
                                {
                                        ::waflz_pb::directive_t* l_drx = NULL;
                                        int32_t l_s;
                                        l_s = create_modified_rule(&l_drx, ao_rx_list, l_tv_map, *l_rule, false);
                                        if(l_s != WAFLZ_STATUS_OK)
                                        {
                                                return WAFLZ_STATUS_ERROR;
                                        }
                                        ao_mx_directive_list.push_back(l_drx);
                                        *i_d = l_drx;
                                        //NDBG_PRINT("RULE: %s\n", l_drx->sec_rule().ShortDebugString().c_str());
                                }
                                ++l_cr_idx;
                        } while (l_cr_idx < l_d.sec_rule().chained_rule_size());
                }
                ++i_d;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::compile(void)
{
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        int32_t l_s;
        l_s = m_engine.compile(*m_compiled_config, *m_pb);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "engine compile reason: %s", m_engine.get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // *************************************************
        //          C O N F I G   U P D A T E S
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // disabled rules
        // -------------------------------------------------
        disabled_rule_id_set_t l_dr_id_set;
        for(int32_t i_dr = 0; i_dr < m_pb->rule_remove_by_id_size(); ++i_dr)
        {
                const std::string &l_dr = m_pb->rule_remove_by_id(i_dr);
                l_dr_id_set.insert(l_dr);
        }
        // -------------------------------------------------
        // rule target updates
        // -------------------------------------------------
        _id_tv_map_t *l_id_tv_map = new _id_tv_map_t();
        _id_tv_map_t *l_id_tv_replace_map = new _id_tv_map_t();
        for(int32_t i_rtu = 0; i_rtu < m_pb->update_target_by_id_size(); ++i_rtu)
        {
                const ::waflz_pb::update_target_t& l_rtu = m_pb->update_target_by_id(i_rtu);
                if(!l_rtu.has_id())
                {
                        continue;
                }
                // -----------------------------------------
                // replace
                // -----------------------------------------
                if(l_rtu.has_replace())
                {
                        if(!l_rtu.replace().empty() &&
                            l_rtu.variable_size() &&
                            l_rtu.variable(0).has_type())
                        {
                                // ---------------------------------
                                // for each match
                                // ---------------------------------
                                const ::waflz_pb::variable_t& l_v = l_rtu.variable(0);
                                for(int32_t i_m = 0; i_m < l_v.match_size(); ++i_m)
                                {
                                        const ::waflz_pb::variable_t_match_t& l_m = l_v.match(i_m);
                                        // -------------------------
                                        // only is negated for now..
                                        // -------------------------
                                        if(!l_m.is_negated())
                                        {
                                                continue;
                                        }
                                        if(l_id_tv_replace_map->find(l_rtu.id()) == l_id_tv_replace_map->end())
                                        {
                                                _type_var_map_t l_tmp;
                                                (*l_id_tv_replace_map)[l_rtu.id()] = l_tmp;
                                        }
                                        _type_var_map_t& l_tv_map = (*l_id_tv_replace_map)[l_rtu.id()];
                                        if(l_tv_map.find(l_v.type()) == l_tv_map.end())
                                        {
                                                waflz_pb::variable_t l_tmp;
                                                l_tmp.set_type(l_v.type());
                                                l_tv_map[l_v.type()] = l_tmp;
                                        }
                                        ::waflz_pb::variable_t& l_rm_v = l_tv_map[l_v.type()];
                                        l_rm_v.add_match()->CopyFrom(l_m);
                                }
                                continue;
                        }
                }
                // -----------------------------------------
                // for each var
                // -----------------------------------------
                for(int32_t i_v = 0; i_v < l_rtu.variable_size(); ++i_v)
                {
                        const ::waflz_pb::variable_t& l_v = l_rtu.variable(i_v);
                        if(!l_v.has_type())
                        {
                                continue;
                        }
                        // ---------------------------------
                        // for each match
                        // ---------------------------------
                        for(int32_t i_m = 0; i_m < l_v.match_size(); ++i_m)
                        {
                                const ::waflz_pb::variable_t_match_t& l_m = l_v.match(i_m);
                                // -------------------------
                                // only is negated for now..
                                // -------------------------
                                if(!l_m.is_negated())
                                {
                                        continue;
                                }
                                if(l_id_tv_map->find(l_rtu.id()) == l_id_tv_map->end())
                                {
                                        _type_var_map_t l_tmp;
                                        (*l_id_tv_map)[l_rtu.id()] = l_tmp;
                                }
                                _type_var_map_t& l_tv_map = (*l_id_tv_map)[l_rtu.id()];
                                if(l_tv_map.find(l_v.type()) == l_tv_map.end())
                                {
                                        waflz_pb::variable_t l_tmp;
                                        l_tmp.set_type(l_v.type());
                                        l_tv_map[l_v.type()] = l_tmp;
                                }
                                ::waflz_pb::variable_t& l_rm_v = l_tv_map[l_v.type()];
                                l_rm_v.add_match()->CopyFrom(l_m);
                        }
                }
        }
        // -------------------------------------------------
        // modifications...
        // -------------------------------------------------
        l_s = modify_directive_list(m_compiled_config->m_directive_list_phase_1,
                                    m_mx_rule_list,
                                    m_compiled_config->m_regex_list,
                                    l_dr_id_set,
                                    *l_id_tv_map,
                                    *l_id_tv_replace_map);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_id_tv_replace_map) { delete l_id_tv_replace_map; l_id_tv_replace_map = NULL; }
                if(l_id_tv_map) { delete l_id_tv_map; l_id_tv_map = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        l_s = modify_directive_list(m_compiled_config->m_directive_list_phase_2,
                                    m_mx_rule_list,
                                    m_compiled_config->m_regex_list,
                                    l_dr_id_set,
                                    *l_id_tv_map,
                                    *l_id_tv_replace_map);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_id_tv_replace_map) { delete l_id_tv_replace_map; l_id_tv_replace_map = NULL; }
                if(l_id_tv_map) { delete l_id_tv_map; l_id_tv_map = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        if(l_id_tv_map) { delete l_id_tv_map; l_id_tv_map = NULL; }
        if(l_id_tv_replace_map) { delete l_id_tv_replace_map; l_id_tv_replace_map = NULL; }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::init(config_parser::format_t a_format,
                  const std::string &a_path,
                  bool a_apply_defaults)
{
        // Check if already is initd
        if(m_is_initd)
        {
                return WAFLZ_STATUS_OK;
        }
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        // -------------------------------------------------
        // set defaults for missing values...
        // -------------------------------------------------
        int32_t l_s;
        waflz_pb::sec_config_t *l_pb = NULL;
        if(a_apply_defaults)
        {
                m_pb = new waflz_pb::sec_config_t();
                l_s = set_defaults();
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        config_parser *l_parser = new config_parser();
        l_pb = new waflz_pb::sec_config_t();
        l_s = l_parser->parse_config(*l_pb, a_format, a_path);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_parser) { delete l_parser; l_parser = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if(m_pb)
        {
                m_pb->MergeFrom(*l_pb);
                delete l_pb;
                l_pb = NULL;
        }
        else
        {
                m_pb = l_pb;
        }
        // TODO remove -debug...
        //l_parser->show_status();
        if(l_parser) { delete l_parser; l_parser = NULL;}
        // -------------------------------------------------
        // set ruleset info
        // -------------------------------------------------
        m_pb->set_ruleset_id("__na__");
        m_pb->set_ruleset_version("__na__");
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        l_s = compile();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_is_initd = true;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void set_var_tx(waflz_pb::sec_config_t &ao_conf_pb,
                const char *a_id,
                const char *a_var,
                const std::string a_val)
{
        ::waflz_pb::sec_action_t* l_a = NULL;
        l_a = ao_conf_pb.add_directive()->mutable_sec_action();
        l_a->set_id(a_id);
        l_a->set_phase(1);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_NONE);
        l_a->set_nolog(true);
        l_a->set_action_type(waflz_pb::sec_action_t_action_type_t_PASS);
        ::waflz_pb::sec_action_t_setvar_t* l_sv = NULL;
        l_sv = l_a->add_setvar();
        l_sv->set_scope(waflz_pb::sec_action_t_setvar_t_scope_t_TX);
        l_sv->set_var(a_var);
        l_sv->set_val(a_val);
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::set_defaults(void)
{
        ::waflz_pb::sec_config_t& l_conf_pb = *m_pb;
        // -------------------------------------------------
        // paranoia config
        // -------------------------------------------------
        set_var_tx(l_conf_pb, "900000", "paranoia_level", "1");
        // -------------------------------------------------
        // anomaly settings
        // -------------------------------------------------
        set_var_tx(l_conf_pb, "900001", "critical_anomaly_score", "5");
        set_var_tx(l_conf_pb, "900002", "error_anomaly_score", "4");
        set_var_tx(l_conf_pb, "900003", "warning_anomaly_score", "3");
        set_var_tx(l_conf_pb, "900004", "notice_anomaly_score", "2");
        set_var_tx(l_conf_pb, "900005", "anomaly_score", "0");
        set_var_tx(l_conf_pb, "900006", "sql_injection_score", "0");
        set_var_tx(l_conf_pb, "900007", "xss_score", "0");
        set_var_tx(l_conf_pb, "900008", "inbound_anomaly_score", "0");
        set_var_tx(l_conf_pb, "900009", "outbound_anomaly_score", "0");
        // -------------------------------------------------
        // changing var names depending on ruleset
        // version...
        // OWASP changed from:
        //   inbound_anomaly_score_level
        //   to
        //   outbound_anomaly_score_threshold
        // -------------------------------------------------
        set_var_tx(l_conf_pb, "900012", "inbound_anomaly_score_level", "1");
        set_var_tx(l_conf_pb, "900013", "outbound_anomaly_score_level", "4");
        set_var_tx(l_conf_pb, "900014", "anomaly_score_blocking", "on");
        // -------------------------------------------------
        // general settings
        // -------------------------------------------------
        set_var_tx(l_conf_pb, "900015", "max_num_args", "512");
        set_var_tx(l_conf_pb, "900016", "arg_name_length", "1024");
        set_var_tx(l_conf_pb, "900017", "arg_length", "8000");
        set_var_tx(l_conf_pb, "900018", "total_arg_length", "64000");
        set_var_tx(l_conf_pb, "900019", "max_file_size", "6291456");
        set_var_tx(l_conf_pb, "900020", "combined_file_sizes", "6291456");
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::init(profile &a_profile, bool a_leave_tmp_file)
{
        if(!a_profile.get_pb())
        {
                return WAFLZ_STATUS_ERROR;
        }
        const ::waflz_pb::profile& l_prof_pb = *(a_profile.get_pb());
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        m_pb = new waflz_pb::sec_config_t();
        ::waflz_pb::sec_config_t& l_conf_pb = *m_pb;
        // -------------------------------------------------
        // general settings
        // -------------------------------------------------
        const ::waflz_pb::profile_general_settings_t& l_gs = l_prof_pb.general_settings();
        // -------------------------------------------------
        // error action...
        // -------------------------------------------------
        {
        ::waflz_pb::sec_rule_t* l_r = NULL;
        ::waflz_pb::variable_t* l_v = NULL;
        ::waflz_pb::variable_t_match_t* l_m = NULL;
        ::waflz_pb::sec_rule_t_operator_t* l_o = NULL;
        ::waflz_pb::sec_action_t* l_a = NULL;
        l_r = l_conf_pb.add_directive()->mutable_sec_rule();
        l_v = l_r->add_variable();
        l_v->set_type(::waflz_pb::variable_t_type_t_TX);
        l_m = l_v->add_match();
        l_m->set_is_regex(true);
        l_m->set_value("^MSC_");
        l_o = l_r->mutable_operator_();
        l_o->set_type(::waflz_pb::sec_rule_t_operator_t_type_t_STREQ);
        l_o->set_is_negated(true);
        l_o->set_value("0");
        l_a = l_r->mutable_action();
        l_a->set_id("200004");
        l_a->set_phase(2);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_NONE);
        l_a->set_action_type(waflz_pb::sec_action_t_action_type_t_DENY);
        l_a->set_msg("ModSecurity internal error flagged: %{MATCHED_VAR_NAME}");
        }
        // -------------------------------------------------
        // paranoia config
        // -------------------------------------------------
        if(m_owasp_ruleset_version >= 300)
        {
        //default
        uint32_t l_paranoia_level = 1;
        if(l_gs.has_paranoia_level() &&
           (l_gs.paranoia_level() > 0))
        {
                l_paranoia_level = l_gs.paranoia_level();
        }
        set_var_tx(l_conf_pb, "900000", "paranoia_level", to_string(l_paranoia_level));
        set_var_tx(l_conf_pb, "900100", "executing_paranoia_level", to_string(l_paranoia_level));
        }
        // -------------------------------------------------
        // anomaly settings
        // -------------------------------------------------
        const ::waflz_pb::profile_general_settings_t_anomaly_settings_t& l_ax = l_gs.anomaly_settings();
        set_var_tx(l_conf_pb, "900001", "critical_anomaly_score", to_string(l_ax.critical_score()));
        set_var_tx(l_conf_pb, "900002", "error_anomaly_score", to_string(l_ax.error_score()));
        set_var_tx(l_conf_pb, "900003", "warning_anomaly_score", to_string(l_ax.warning_score()));
        set_var_tx(l_conf_pb, "900004", "notice_anomaly_score", to_string(l_ax.notice_score()));
        set_var_tx(l_conf_pb, "900005", "anomaly_score", "0");
        set_var_tx(l_conf_pb, "900006", "sql_injection_score", "0");
        set_var_tx(l_conf_pb, "900007", "xss_score", "0");
        set_var_tx(l_conf_pb, "900008", "inbound_anomaly_score", "0");
        set_var_tx(l_conf_pb, "900009", "outbound_anomaly_score", "0");
        // -------------------------------------------------
        // changing var names depending on ruleset
        // version...
        // OWASP changed from:
        //   inbound_anomaly_score_level
        //   to
        //   outbound_anomaly_score_threshold
        // -------------------------------------------------
        if(m_owasp_ruleset_version >= 300)
        {
        set_var_tx(l_conf_pb, "900010", "inbound_anomaly_score_threshold", to_string(l_ax.inbound_threshold()));
        set_var_tx(l_conf_pb, "900011", "outbound_anomaly_score_threshold", to_string(l_ax.outbound_threshold()));
        }
        else
        {
        set_var_tx(l_conf_pb, "900012", "inbound_anomaly_score_level", to_string(l_ax.inbound_threshold()));
        set_var_tx(l_conf_pb, "900013", "outbound_anomaly_score_level", to_string(l_ax.outbound_threshold()));
        }
        set_var_tx(l_conf_pb, "900014", "anomaly_score_blocking", "on");
        // -------------------------------------------------
        // general settings
        // -------------------------------------------------
        set_var_tx(l_conf_pb, "900015", "max_num_args", to_string(l_gs.max_num_args()));
        set_var_tx(l_conf_pb, "900016", "arg_name_length", to_string(l_gs.arg_name_length()));
        set_var_tx(l_conf_pb, "900017", "arg_length", to_string(l_gs.arg_length()));
        set_var_tx(l_conf_pb, "900018", "total_arg_length", to_string(l_gs.total_arg_length()));
        set_var_tx(l_conf_pb, "900019", "max_file_size", to_string(l_gs.max_file_size()));
        set_var_tx(l_conf_pb, "900020", "combined_file_sizes", to_string(l_gs.combined_file_sizes()));
        // -------------------------------------------------
        // allowed http methods
        // -------------------------------------------------
        std::string l_alw_mth;
        if(!l_gs.allowed_http_methods_size())
        {
                WAFLZ_PERROR(m_err_msg, "No allowed http methods provided.  Would block all traffic.  Not applying.");
                return WAFLZ_STATUS_ERROR;
        }
        for(int32_t i_ahm = 0; i_ahm < l_gs.allowed_http_methods_size(); ++i_ahm)
        {
                // for each allowed http method
                l_alw_mth.append(l_gs.allowed_http_methods(i_ahm));
                // append space if not last
                if((i_ahm + 1) < l_gs.allowed_http_methods_size())
                {
                        l_alw_mth.append(" ");
                }
        }
        set_var_tx(l_conf_pb, "900021", "allowed_methods", l_alw_mth);
        // -------------------------------------------------
        // allowed_request_content_types
        // -------------------------------------------------
        if(!l_gs.allowed_request_content_types_size())
        {
                WAFLZ_PERROR(m_err_msg, "No allowed http request content-types provided.  Could block all traffic.  Not applying.");
                return WAFLZ_STATUS_ERROR;
        }
        std::string l_alw_rct;
        for(int32_t i_arct = 0; i_arct < l_gs.allowed_request_content_types_size(); ++i_arct)
        {
                // for each allowed content type
                l_alw_rct.append(l_gs.allowed_request_content_types(i_arct));
                // append space if not last
                if((i_arct + 1) < l_gs.allowed_request_content_types_size())
                {
                        l_alw_rct.append("|");
                }
        }
        set_var_tx(l_conf_pb, "900022", "allowed_request_content_type", l_alw_rct);
        // -------------------------------------------------
        // allowed_http_versions
        // -------------------------------------------------
        set_var_tx(l_conf_pb, "900023", "allowed_http_versions", "HTTP/1.1");
        // -------------------------------------------------
        // disallowed_extensions
        // -------------------------------------------------
        std::string l_dis_ext;
        for(int32_t i_dx = 0; i_dx < l_gs.disallowed_extensions_size(); ++i_dx)
        {
                // for each allowed http method
                l_dis_ext.append(l_gs.disallowed_extensions(i_dx));
                // append space if not last
                if((i_dx + 1) < l_gs.disallowed_extensions_size())
                {
                        l_dis_ext.append("/ ");
                }
        }
        set_var_tx(l_conf_pb, "900024", "restricted_extensions", l_dis_ext);
        // -------------------------------------------------
        // disallowed_headers
        // -------------------------------------------------
        std::string l_dis_hdr;
        for(int32_t i_dh = 0; i_dh < l_gs.disallowed_headers_size(); ++i_dh)
        {
                // for each allowed http method
                l_dis_hdr.append("/");
                // ---------------------------------------
                // Due to our customizations to this rule,
                // to get it to actually work properly
                // (See [SECC-115])
                // we need to md5 the headers
                // ---------------------------------------
                std::string l_dh = l_gs.disallowed_headers(i_dh);
                md5_hasher md5_header;
                md5_header.update(l_dh.c_str(), l_dh.length());
                l_dis_hdr.append(md5_header.hash_str());
                // append space if not last
                if((i_dh + 1) < l_gs.disallowed_headers_size())
                {
                        l_dis_hdr.append("/ ");
                }
                else
                {
                        l_dis_hdr.append("/");
                }
        }
        set_var_tx(l_conf_pb, "900025", "restricted_headers", l_dis_hdr);
        // -------------------------------------------------
        // validate utf8 encoding please
        // -------------------------------------------------
        if(l_gs.validate_utf8_encoding())
        {
                set_var_tx(l_conf_pb, "900026", "crs_validate_utf8_encoding", to_string(1));
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        {
        ::waflz_pb::sec_rule_t* l_r = NULL;
        ::waflz_pb::variable_t* l_v = NULL;
        ::waflz_pb::variable_t_match_t* l_m = NULL;
        ::waflz_pb::sec_rule_t_operator_t* l_o = NULL;
        ::waflz_pb::sec_action_t* l_a = NULL;
        ::waflz_pb::sec_action_t_setvar_t* l_sv = NULL;
        l_r = l_conf_pb.add_directive()->mutable_sec_rule();
        l_v = l_r->add_variable();
        l_v->set_type(::waflz_pb::variable_t_type_t_REQUEST_HEADERS);
        l_m = l_v->add_match();
        l_m->set_value("User-Agent");
        l_o = l_r->mutable_operator_();
        l_o->set_type(::waflz_pb::sec_rule_t_operator_t_type_t_RX);
        l_o->set_is_regex(true);
        l_o->set_value("^(.*)$");
        l_a = l_r->mutable_action();
        l_a->set_id("900027");
        l_a->set_phase(1);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_NONE);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_SHA1);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_HEXENCODE);
        l_a->set_action_type(waflz_pb::sec_action_t_action_type_t_PASS);
        l_a->set_msg("__na__");
        l_sv = l_a->add_setvar();
        l_sv->set_scope(waflz_pb::sec_action_t_setvar_t_scope_t_TX);
        l_sv->set_var("ua_hash");
        l_sv->set_val("%{matched_var}");
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        {
        ::waflz_pb::sec_rule_t* l_r = NULL;
        ::waflz_pb::variable_t* l_v = NULL;
        ::waflz_pb::sec_rule_t_operator_t* l_o = NULL;
        ::waflz_pb::sec_action_t* l_a = NULL;
        ::waflz_pb::sec_action_t_setvar_t* l_sv = NULL;
        l_r = l_conf_pb.add_directive()->mutable_sec_rule();
        l_v = l_r->add_variable();
        l_v->set_type(::waflz_pb::variable_t_type_t_REMOTE_ADDR);
        l_o = l_r->mutable_operator_();
        l_o->set_type(::waflz_pb::sec_rule_t_operator_t_type_t_RX);
        l_o->set_is_regex(true);
        l_o->set_value("^(.*)$");
        l_a = l_r->mutable_action();
        l_a->set_id("900028");
        l_a->set_phase(1);
        l_a->set_capture(true);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_NONE);
        l_a->set_action_type(waflz_pb::sec_action_t_action_type_t_PASS);
        l_a->set_msg("__na__");
        l_sv = l_a->add_setvar();
        l_sv->set_scope(waflz_pb::sec_action_t_setvar_t_scope_t_TX);
        l_sv->set_var("real_ip");
        l_sv->set_val("%{tx.1}");
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        {
        ::waflz_pb::sec_rule_t* l_r = NULL;
        ::waflz_pb::variable_t* l_v = NULL;
        ::waflz_pb::variable_t_match_t* l_m = NULL;
        ::waflz_pb::sec_rule_t_operator_t* l_o = NULL;
        ::waflz_pb::sec_action_t* l_a = NULL;
        l_r = l_conf_pb.add_directive()->mutable_sec_rule();
        l_v = l_r->add_variable();
        l_v->set_is_count(true);
        l_v->set_type(::waflz_pb::variable_t_type_t_TX);
        l_m = l_v->add_match();
        l_m->set_value("REAL_IP");
        l_o = l_r->mutable_operator_();
        l_o->set_type(::waflz_pb::sec_rule_t_operator_t_type_t_EQ);
        l_o->set_value("0");
        l_a = l_r->mutable_action();
        l_a->set_id("900029");
        l_a->set_phase(1);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_NONE);
        l_a->set_action_type(waflz_pb::sec_action_t_action_type_t_PASS);
        l_a->set_msg("__na__");
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        {
        ::waflz_pb::sec_rule_t* l_r = NULL;
        ::waflz_pb::variable_t* l_v = NULL;
        ::waflz_pb::variable_t_match_t* l_m = NULL;
        ::waflz_pb::sec_rule_t_operator_t* l_o = NULL;
        ::waflz_pb::sec_action_t* l_a = NULL;
        ::waflz_pb::sec_action_t_setvar_t* l_sv = NULL;
        l_r = l_conf_pb.add_directive()->mutable_sec_rule();
        l_v = l_r->add_variable();
        l_v->set_is_count(true);
        l_v->set_type(::waflz_pb::variable_t_type_t_TX);
        l_m = l_v->add_match();
        l_m->set_value("REAL_IP");
        l_o = l_r->mutable_operator_();
        l_o->set_type(::waflz_pb::sec_rule_t_operator_t_type_t_EQ);
        l_o->set_value("0");
        l_a = l_r->mutable_action();
        l_a->set_id("900030");
        l_a->set_phase(1);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_NONE);
        l_a->set_action_type(waflz_pb::sec_action_t_action_type_t_PASS);
        l_a->set_msg("__na__");
        l_sv = l_a->add_setvar();
        l_sv->set_scope(waflz_pb::sec_action_t_setvar_t_scope_t_TX);
        l_sv->set_var("real_ip");
        l_sv->set_val("%{remote_addr}");
        }
        // -------------------------------------------------
        // The CRS checks the tx.crs_setup_version variable
        // to ensure that the setup has been loaded. If not
        // planning to use this setup template manually set
        // tx.crs_setup_version variable before including
        // the CRS rules/* files.
        //
        // The variable is a numerical representation of the
        // CRS version number.
        // E.g., v3.0.0 is represented as 300.
        // -------------------------------------------------
        set_var_tx(l_conf_pb, "900990", "crs_setup_version", to_string(m_owasp_ruleset_version));
        // -------------------------------------------------
        // conf file functor
        // -------------------------------------------------
        // look at list of config files and strip
        // disabled ones
        // -------------------------------------------------
        class is_conf_file
        {
        public:
                static int compare(const struct dirent* a_dirent)
                {
                        //TRACE("Looking at file: '%s'", a_dirent->d_name);
                        switch (a_dirent->d_name[0])
                        {
                        case 'a' ... 'z':
                        case 'A' ... 'Z':
                        case '0' ... '9':
                        case '_':
                        {
                                // valid path name to consider
                                const char* l_found = NULL;
                                // look for the .conf suffix
                                l_found = ::strcasestr(a_dirent->d_name, ".conf");
                                if(l_found == NULL)
                                {
                                        // not a .conf file
                                        //NDBG_PRINT("Failed to find .conf or .conf.json suffix\n");
                                        goto done;
                                }
                                if(::strlen(l_found) != 5 &&
                                   ::strlen(l_found) != 10)
                                {
                                        // failed to find .conf right at the end
                                        //NDBG_PRINT("found in the wrong place. %zu\n", ::strlen(l_found));
                                        goto done;
                                }
                                // we want this file
                                return 1;
                                break;
                        }
                        default:
                                //TRACE("Found invalid first char: '%c'", a_dirent->d_name[0]);
                                goto done;
                        }
done:
                        return 0;
                }
        };
        // -------------------------------------------------
        // construct ruleset dir
        // -------------------------------------------------
        l_conf_pb.set_ruleset_id(l_prof_pb.ruleset_id());
        l_conf_pb.set_ruleset_version(l_prof_pb.ruleset_version());
        {
        struct dirent** l_conf_list;
        std::string l_ruleset_dir = a_profile.s_ruleset_dir;
        l_ruleset_dir.append(l_prof_pb.ruleset_id());
        l_ruleset_dir.append("/version/");
        l_ruleset_dir.append(l_prof_pb.ruleset_version());
        l_ruleset_dir.append("/policy/");
        // -------------------------------------------------
        // set ruleset dir for engine before it compiles
        // -------------------------------------------------
        m_engine.set_ruleset_dir(l_ruleset_dir);
        // -------------------------------------------------
        // scan ruleset dir
        // -------------------------------------------------
        int l_num_files = -1;
        l_num_files = ::scandir(l_ruleset_dir.c_str(),
                                &l_conf_list,
                                is_conf_file::compare,
                                alphasort);
        if(l_num_files == -1)
        {
                // failed to build the list of directory entries
                WAFLZ_PERROR(m_err_msg, "Failed to compile modsecurity json instance-profile settings.  Reason: failed to scan profile directory: %s: %s", l_ruleset_dir.c_str(), (errno == 0 ? "unknown" : strerror(errno)));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // include policies
        // -------------------------------------------------
        typedef std::set<std::string> policy_t;
        if(l_prof_pb.policies_size())
        {
                policy_t l_enable_policies;
                for(int32_t i_p = 0; i_p < l_prof_pb.policies_size(); ++i_p)
                {
                        l_enable_policies.insert(l_prof_pb.policies(i_p));
                }
                for(int32_t i_f = 0; i_f < l_num_files; ++i_f)
                {
                        if(l_enable_policies.find(l_conf_list[i_f]->d_name) != l_enable_policies.end())
                        {
                                std::string &l_inc = *(l_conf_pb.add_directive()->mutable_include());
                                l_inc.append(l_ruleset_dir);
                                l_inc.append(l_conf_list[i_f]->d_name);
                        }
                        if(l_conf_list[i_f])
                        {
                                free(l_conf_list[i_f]);
                                l_conf_list[i_f] = NULL;
                        }
                }
        }
        // -------------------------------------------------
        // exclude policies
        // -------------------------------------------------
        else
        {
                policy_t l_disabled_policies;
                for(int32_t i_p = 0; i_p < l_prof_pb.disabled_policies_size(); ++i_p)
                {
                        l_disabled_policies.insert(l_prof_pb.disabled_policies(i_p).policy_id());
                }
                for(int32_t i_f = 0; i_f < l_num_files; ++i_f)
                {
                        if(l_disabled_policies.find(l_conf_list[i_f]->d_name) == l_disabled_policies.end())
                        {
                                std::string &l_inc = *(l_conf_pb.add_directive()->mutable_include());
                                l_inc.append(l_ruleset_dir);
                                l_inc.append(l_conf_list[i_f]->d_name);
                        }
                        if(l_conf_list[i_f])
                        {
                                free(l_conf_list[i_f]);
                                l_conf_list[i_f] = NULL;
                        }
                }
        }
        if(l_conf_list)
        {
                free(l_conf_list);
                l_conf_list = NULL;
        }
        }
        // -------------------------------------------------
        // disable rules
        // -------------------------------------------------
        // disable the rules with the given ids
        // -------------------------------------------------
        for(int32_t i_r = 0; i_r < l_prof_pb.disabled_rules_size(); ++i_r)
        {
                if(!l_prof_pb.disabled_rules(i_r).has_rule_id() ||
                   l_prof_pb.disabled_rules(i_r).rule_id().empty())
                {
                        continue;
                }
                l_conf_pb.add_rule_remove_by_id(l_prof_pb.disabled_rules(i_r).rule_id());
        }
        // -------------------------------------------------
        // rule target updates
        // -------------------------------------------------
        // update the targets for a given rule
        // "rule_target_updates": [
        //     {
        //         "rule_id": "981172",
        //         "target": "ARGS",
        //         "target_match": "email",
        //         "is_regex": false,
        //         "is_negated": true,
        //         "replace_target": ""
        //     }
        // ]
        // -------------------------------------------------
        for(int32_t i_rtu = 0; i_rtu < l_prof_pb.rule_target_updates_size(); ++i_rtu)
        {
                const ::waflz_pb::profile_rule_target_update_t& l_rtu = l_prof_pb.rule_target_updates(i_rtu);
                if(!l_rtu.has_rule_id() ||
                   !l_rtu.has_target())
                {
                       continue;
                }
                ::waflz_pb::update_target_t& l_ut = *(l_conf_pb.add_update_target_by_id());
                l_ut.set_id(l_rtu.rule_id());
                if(l_rtu.has_replace_target())
                {
                        l_ut.set_replace(l_rtu.replace_target());
                }
                ::waflz_pb::variable_t& l_var = *(l_ut.add_variable());
                // -----------------------------------------
                // add match...
                // -----------------------------------------
                if(l_rtu.has_target_match())
                {
                        ::waflz_pb::variable_t_match_t& l_match = *(l_var.add_match());
                        l_match.set_value(l_rtu.target_match());
                        // set is_negated by default
                        l_match.set_is_negated(true);
                        if(l_rtu.is_regex())
                        {
                                l_match.set_is_regex(true);
                        }
                }
                // -----------------------------------------
                // str to type reflection...
                // -----------------------------------------
                const google::protobuf::Descriptor* l_des = l_var.GetDescriptor();
                const google::protobuf::Reflection* l_ref = l_var.GetReflection();
                const google::protobuf::FieldDescriptor* l_f = l_des->FindFieldByName("type");
                if(l_f == NULL)
                {
                        WAFLZ_PERROR(m_err_msg, "can't find field by type");
                        return WAFLZ_STATUS_ERROR;
                }
                const google::protobuf::EnumValueDescriptor* l_desc =
                                waflz_pb::variable_t_type_t_descriptor()->FindValueByName(l_rtu.target());
                if(l_desc == NULL)
                {
                        WAFLZ_PERROR(m_err_msg, "invalid rule target update target type spec: %s", l_rtu.target().c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                l_ref->SetEnum(&l_var, l_f, l_desc);
                //NDBG_PRINT("rtu: %s\n", l_ut.ShortDebugString().c_str());
        }
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        int32_t l_s;
        l_s = compile();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_is_initd = true;
        return WAFLZ_STATUS_OK;
}
#if 0
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::init_line(config_parser::format_t a_format, const std::string &a_line)
{
         // Check if already is initd
        if(m_is_initd)
        {
                return WAFLZ_STATUS_OK;
        }
        int32_t l_s;
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        l_s = m_parser.parse_line(a_format, m_pb, a_line);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error\n");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // set ruleset info
        // -------------------------------------------------
        m_pb->set_ruleset_id("__na__");
        m_pb->set_ruleset_version("__na__");
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        l_s = compile();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_is_initd = true;
        return WAFLZ_STATUS_OK;
}
#endif
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::process_rule(waflz_pb::event **ao_event,
                          const waflz_pb::sec_rule_t &a_rule,
                          rqst_ctx &a_ctx)
{
        //NDBG_PRINT("**********************************************\n");
        //NDBG_PRINT("*                 R U L E                     \n");
        //NDBG_PRINT("**********************************************\n");
        //NDBG_PRINT("rule: %s\n", a_rule.ShortDebugString().c_str());
        // -------------------------------------------------
        // chain rule loop
        // -------------------------------------------------
        const waflz_pb::sec_rule_t *l_rule = NULL;
        int32_t l_cr_idx = -1;
        bool i_match = false;
        do {
                //NDBG_PRINT("RULE[%4d]************************************\n", l_cr_idx);
                //NDBG_PRINT("l_cr_idx: %d\n", l_cr_idx);
                if(l_cr_idx == -1)
                {
                        l_rule = &a_rule;
                }
                else if((l_cr_idx >= 0) &&
                        (l_cr_idx < a_rule.chained_rule_size()))
                {
                        l_rule = &(a_rule.chained_rule(l_cr_idx));
                }
                else
                {
                        //WAFLZ_PERROR(m_err_msg, "bad chained rule idx: %d -size: %d",
                        //             l_cr_idx,
                        //             a_rule.chained_rule_size());
                        return WAFLZ_STATUS_ERROR;
                }
                //show_rule_info(a_rule);
                // Get action
                if(!l_rule->has_action())
                {
                        // TODO is OK???
                        ++l_cr_idx;
                        continue;
                }
                if(!l_rule->has_operator_())
                {
                        // TODO this aight???
                        // TODO is OK???
                        ++l_cr_idx;
                        continue;
                }
                int32_t l_s;
                i_match = false;
                l_s = process_rule_part(ao_event,
                                        i_match,
                                        *l_rule,
                                        a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        //WAFLZ_PERROR(m_err_msg, "bad chained rule idx: %d -size: %d",
                        //             l_cr_idx,
                        //             a_rule.chained_rule_size());
                        return WAFLZ_STATUS_ERROR;
                }
                if(!i_match)
                {
                        // bail out on first un-matched...
                        return WAFLZ_STATUS_OK;
                }
                ++l_cr_idx;
        } while(l_cr_idx < a_rule.chained_rule_size());
        // -------------------------------------------------
        // never matched...
        // -------------------------------------------------
        if(!i_match)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // matched...
        // -------------------------------------------------
        //NDBG_PRINT("%sMATCH%s: !!!\n%s%s%s\n",
        //           ANSI_COLOR_BG_RED, ANSI_COLOR_OFF,
        //           ANSI_COLOR_FG_RED, a_rule.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        if(!a_rule.has_action())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // run disruptive action...
        // -------------------------------------------------
        // TODO !!!
        //NDBG_PRINT("%sACTIONS%s: !!!\n%s%s%s\n",
        //           ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF,
        //           ANSI_COLOR_FG_MAGENTA, a_rule.action().ShortDebugString().c_str(), ANSI_COLOR_OFF);
#if 0
        for(int32_t i_s = 0; i_s < a_rule.action().setvar_size(); ++i_s)
        {
                const ::waflz_pb::sec_action_t_setvar_t& l_sv = a_rule.action().setvar(i_s);
                NDBG_PRINT("%sSET_VAR%s: %s%s%s\n",
                           ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF,
                           ANSI_COLOR_FG_GREEN, l_sv.ShortDebugString().c_str(), ANSI_COLOR_OFF);

        }
#endif
        // -------------------------------------------------
        // process match
        // -------------------------------------------------
#if 0
        {
        std::string l_id = "NA";
        if(a_rule.action().has_id()) { l_id = a_rule.action().id(); }
        std::string l_msg = "NA";
        if(a_rule.action().has_msg()) { l_msg = a_rule.action().msg(); }
        NDBG_OUTPUT("MATCHED: id: %16s :: msg: %s\n", l_id.c_str(), l_msg.c_str());
        }
#endif
        int32_t l_s;
        l_s = process_match(ao_event, a_rule, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error processing rule\n");
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::process_rule_part(waflz_pb::event **ao_event,
                               bool &ao_match,
                               const waflz_pb::sec_rule_t &a_rule,
                               rqst_ctx &a_ctx)
{
        macro *l_macro =  &(m_engine.get_macro());
        ao_match = false;
        const waflz_pb::sec_action_t &l_a = a_rule.action();
        bool l_multimatch = l_a.multimatch();
        // -----------------------------------------
        // get operator
        // -----------------------------------------
        if(!a_rule.has_operator_() ||
           !a_rule.operator_().has_type())
        {
                // TODO log error -shouldn't happen???
                return WAFLZ_STATUS_OK;
        }
        const ::waflz_pb::sec_rule_t_operator_t& l_op = a_rule.operator_();
        op_t l_op_cb = NULL;
        l_op_cb = get_op_cb(l_op.type());
        // -----------------------------------------
        // variable loop
        // -----------------------------------------
        uint32_t l_var_count = 0;
        for(int32_t i_var = 0; i_var < a_rule.variable_size(); ++i_var)
        {
                // -----------------------------------------
                // get var cb
                // -----------------------------------------
                const waflz_pb::variable_t& l_var = a_rule.variable(i_var);
                if(!l_var.has_type())
                {
                        return WAFLZ_STATUS_OK;
                }
                get_var_t l_get_var = NULL;
                l_get_var = get_var_cb(l_var.type());
                if(!l_get_var)
                {
                        return WAFLZ_STATUS_OK;
                }
                int32_t l_s;
                const char *l_x_data;
                uint32_t l_x_len;
                // -----------------------------------------
                // extract list of data
                // -----------------------------------------
                const_arg_list_t l_data_list;
                l_s = l_get_var(l_data_list, l_var_count, l_var, &a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // Handle count first
                // -----------------------------------------
                if(l_var.is_count())
                {
                        std::string l_v_c = to_string(l_var_count);
                        l_x_data = l_v_c.c_str();
                        l_x_len = l_v_c.length();
                        bool l_match = false;
                        if(!l_op_cb)
                        {
                                continue;
                        }
                        l_s = l_op_cb(l_match, l_op, l_x_data, l_x_len, l_macro, &a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO log reason???
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(!l_match)
                        {
                                continue;
                        }
                        // Reflect Variable name
                        const google::protobuf::EnumValueDescriptor* l_var_desc =
                                        waflz_pb::variable_t_type_t_descriptor()->FindValueByNumber(l_var.type());
                        a_ctx.m_cx_matched_var.assign(l_x_data, l_x_len);
                        a_ctx.m_cx_matched_var_name = l_var_desc->name();
                        ao_match = true;
                        break;
                }
                // -----------------------------------------
                // data loop
                // -----------------------------------------
                for(const_arg_list_t::const_iterator i_v = l_data_list.begin();
                    i_v != l_data_list.end();
                    ++i_v)
                {
                        // ---------------------------------
                        // transformation loop
                        // ---------------------------------
                        // ---------------------------------
                        // Set size to at least one if no tx
                        // specified
                        // ---------------------------------
                        int32_t l_t_size = l_a.t_size() ? l_a.t_size() : 1;
                        l_x_data = i_v->m_val;
                        l_x_len = i_v->m_val_len;
                        //NDBG_PRINT("VAR: [%d]: %.*s\n", l_x_len, l_x_len, l_x_data);
                        bool l_mutated = false;
                        for(int32_t i_t = 0; i_t < l_t_size; ++i_t)
                        {
                                // -------------------------
                                // *************************
                                //           T X
                                // *************************
                                // -------------------------
                                waflz_pb::sec_action_t_transformation_type_t l_t_type = waflz_pb::sec_action_t_transformation_type_t_NONE;
                                if(i_t > 1 ||
                                   l_a.t_size())
                                {
                                        l_t_type = l_a.t(i_t);
                                }
                                if(l_t_type == waflz_pb::sec_action_t_transformation_type_t_NONE)
                                {
                                        goto run_op;
                                }
                                // -------------------------
                                // if tx...
                                // -------------------------
                                {
                                tx_cb_t l_tx_cb = NULL;
                                l_tx_cb = get_tx_cb(l_t_type);
                                if(!l_tx_cb)
                                {
                                        continue;
                                }
                                char *l_tx_data = NULL;
                                uint32_t l_tx_len = 0;
                                l_s = l_tx_cb(&l_tx_data, l_tx_len, l_x_data, l_x_len);
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        // TODO log reason???
                                        return WAFLZ_STATUS_ERROR;
                                }
                                if(l_mutated)
                                {
                                        free(const_cast <char *>(l_x_data));
                                        l_x_len = 0;
                                        l_mutated = false;
                                }
                                l_mutated = true;
                                l_x_data = l_tx_data;
                                l_x_len = l_tx_len;
                                // -------------------------
                                // break if no data
                                // no point in transforming
                                // or matching further
                                // -------------------------
                                if(!l_x_data ||
                                   !l_x_len)
                                {
                                        break;
                                }
                                }
run_op:
                                // -------------------------
                                // skip op if:
                                // not multimatch
                                // AND
                                // not the end of the list
                                // -------------------------
                                if(!l_multimatch &&
                                   (i_t != (l_t_size - 1)))
                                {
                                        continue;
                                }
                                // -------------------------
                                // *************************
                                //           O P
                                // *************************
                                // -------------------------
                                if(!l_op_cb)
                                {
                                        // TODO log error -shouldn't happen???
                                        continue;
                                }
                                bool l_match = false;
                                l_s = l_op_cb(l_match, l_op, l_x_data, l_x_len, l_macro, &a_ctx);
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        // TODO log reason???
                                        return WAFLZ_STATUS_ERROR;
                                }
                                if(!l_match)
                                {
                                        continue;
                                }
                                // Reflect Variable name
                                const google::protobuf::EnumValueDescriptor* l_var_desc =
                                                waflz_pb::variable_t_type_t_descriptor()->FindValueByNumber(l_var.type());
                                a_ctx.m_cx_matched_var.assign(l_x_data, l_x_len);
                                a_ctx.m_cx_matched_var_name = l_var_desc->name();
                                a_ctx.m_cx_matched_var_name += ":";
                                a_ctx.m_cx_matched_var_name.append(i_v->m_key, i_v->m_key_len);
                                //NDBG_PRINT("%sMATCH%s: !!!%s%s%s\n",
                                //           ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF,
                                //           ANSI_COLOR_FG_MAGENTA, a_rule.ShortDebugString().c_str(), ANSI_COLOR_OFF);
                                ao_match = true;
                                break;
                        }
                        // ---------------------------------
                        // final cleanup
                        // ---------------------------------
                        if(l_mutated)
                        {
                                free(const_cast <char *>(l_x_data));
                                l_x_data = NULL;
                                l_x_len = 0;
                                l_mutated = false;
                        }
                        // ---------------------------------
                        // got a match -outtie
                        // ---------------------------------
                        if(ao_match)
                        {
                                break;
                        }
                }
                // -----------------------------------------
                // got a match -outtie
                // -----------------------------------------
                if(ao_match)
                {
                        break;
                }
        }
        // -------------------------------------------------
        // *************************************************
        //                A C T I O N S
        // *************************************************
        // -------------------------------------------------
        if(ao_match)
        {
#define _SET_RULE_INFO(_field, _str) \
if(l_a.has_##_field()) { \
data_t l_k; l_k.m_data = _str; l_k.m_len = sizeof(_str) - 1; \
data_t l_v; \
l_v.m_data = l_a._field().c_str(); \
l_v.m_len = l_a._field().length(); \
a_ctx.m_cx_rule_map[l_k] = l_v; \
}
                // -----------------------------------------
                // set rule info
                // -----------------------------------------
                _SET_RULE_INFO(id, "id");
                _SET_RULE_INFO(msg, "msg");
                // -----------------------------------------
                // TODO -only run
                // non-disruptive???
                // -----------------------------------------
                int32_t l_s = process_action_nd(l_a, a_ctx);
                if(l_s == WAFLZ_STATUS_ERROR)
                {
                        NDBG_PRINT("error executing action");
                }
                //NDBG_PRINT("%sACTIONS%s: !!!\n%s%s%s\n",
                //           ANSI_COLOR_BG_CYAN, ANSI_COLOR_OFF,
                //           ANSI_COLOR_FG_CYAN, l_a.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        }
        // -------------------------------------------------
        // null out any set skip values
        // -------------------------------------------------
        else
        {
                a_ctx.m_skip = 0;
                a_ctx.m_skip_after = NULL;
        }
#if 0
        +---------------------------------+----------+
        | Actions                         | Count    |
        +---------------------------------+----------+
        | block                           |      186 |
        | capture                         |      175 |
        | deny                            |        4 |
        | drop                            |        2 |
        | expirevar                       |       16 |
        | nolog                           |      257 |
        | pass                            |      273 |
        | setvar                          |      814 |
        | skip                            |        2 |
        | skipafter                       |      188 |
        +---------------------------------+----------+
#endif
        return WAFLZ_STATUS_OK;
}
/// ----------------------------------------------------------------------------
/// @brief  process the actions in modsec directive or inside a rule
/// @param  a_action, request context
/// @return WAFLZ_STATUS_ERROR or WAFLZ_STATUS_OK
/// ----------------------------------------------------------------------------
int32_t waf::process_action_nd(const waflz_pb::sec_action_t &a_action,
                               rqst_ctx &a_ctx)
{
        // -------------------------------------------------
        // check for skip
        // -------------------------------------------------
        if(a_action.has_skip() &&
           (a_action.skip() > 0))
        {
                a_ctx.m_skip = a_action.skip();
                a_ctx.m_skip_after = NULL;
        }
        // -------------------------------------------------
        // check for skipafter
        // -------------------------------------------------
        if(a_action.has_skipafter() &&
           !a_action.skipafter().empty())
        {
                a_ctx.m_skip = a_action.skip();
                a_ctx.m_skip_after = a_action.skipafter().c_str();
        }
        // -------------------------------------------------
        // for each var
        // -------------------------------------------------
        macro &l_macro = m_engine.get_macro();
        for(int32_t i_sv = 0; i_sv < a_action.setvar_size(); ++i_sv)
        {
                const ::waflz_pb::sec_action_t_setvar_t& l_sv = a_action.setvar(i_sv);
                //NDBG_PRINT("%ssetvar%s: %s%s%s\n",
                //           ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF,
                //           ANSI_COLOR_FG_GREEN, l_sv.ShortDebugString().c_str(), ANSI_COLOR_OFF);
                //------------------------------------------
                // var expansion
                //------------------------------------------
                const ::std::string& l_var = l_sv.var();
                const std::string *l_var_ref = &l_var;
                std::string l_sv_var;
                if(l_macro.has(l_var))
                {
                        //NDBG_PRINT("%ssetvar%s: VAR!!!!\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
                        int32_t l_s;
                        l_s = l_macro(l_sv_var, l_var, &a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        l_var_ref = &l_sv_var;
                }
                //------------------------------------------
                // val expansion
                //------------------------------------------
                const ::std::string& l_val = l_sv.val();
                const std::string *l_val_ref = &l_val;
                std::string l_sv_val;
                if(l_macro.has(l_val))
                {
                        //NDBG_PRINT("%ssetvar%s: VAL!!!!\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
                        int32_t l_s;
                        l_s = l_macro(l_sv_val, l_val, &a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        l_val_ref = &l_sv_val;
                }
                //------------------------------------------
                // *****************************************
                //               S C O P E
                // *****************************************
                //------------------------------------------
                switch(l_sv.scope())
                {
                // -----------------------------------------
                // TX
                // -----------------------------------------
                case ::waflz_pb::sec_action_t_setvar_t_scope_t_TX:
                {
                        cx_map_t &l_cx_map = a_ctx.m_cx_tx_map;
                        //----------------------------------
                        // *********************************
                        //              O P
                        // *********************************
                        //----------------------------------
                        switch(l_sv.op())
                        {
                        //----------------------------------
                        // ASSIGN
                        //----------------------------------
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_ASSIGN:
                        {
                                l_cx_map[*l_var_ref] =  *l_val_ref;
                                break;
                        }
                        //----------------------------------
                        // DELETE
                        //----------------------------------
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_DELETE:
                        {
                                cx_map_t::iterator i_t = l_cx_map.find(*l_var_ref);
                                if(i_t != l_cx_map.end())
                                {
                                        l_cx_map.erase(i_t);
                                }
                                break;
                        }
                        //----------------------------------
                        // INCREMENT
                        //----------------------------------
                        // e.g setvar:tx.rfi_score=+%{tx.critical_anomaly_score}
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_INCREMENT:
                        {
                                int32_t l_pv = 0;
                                cx_map_t::iterator i_t = l_cx_map.find(*l_var_ref);
                                // -------------------------
                                // TODO -use strntol instead
                                // of atoi...
                                // -------------------------
#if 0
                                int32_t l_in_val;
                                char *l_end_ptr = NULL;
                                l_in_val = strntol(a_buf, a_len, &l_end_ptr, 10);
                                if((l_in_val == LONG_MAX) ||
                                   (l_in_val == LONG_MIN))
                                {
                                        return WAFLZ_STATUS_OK;
                                }
                                if(l_end_ptr == a_buf)
                                {
                                        return WAFLZ_STATUS_OK;
                                }
#endif
                                if(i_t != l_cx_map.end())
                                {
                                        l_pv = atoi(i_t->second.c_str());
                                }
                                int32_t l_nv = 0;
                                l_nv = atoi(l_val_ref->c_str());
                                //NDBG_PRINT("INC: var[%s]: %d by: %d\n", l_var_ref->c_str(), l_pv, l_nv);
                                char l_val_str[8];
                                snprintf(l_val_str, 8, "%d", l_pv + l_nv);
                                l_cx_map[*l_var_ref] = l_val_str;
                                break;
                        }
                        //----------------------------------
                        // DECREMENT
                        //----------------------------------
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_DECREMENT:
                        {
                                int32_t l_pv = 0;
                                cx_map_t::iterator i_t = l_cx_map.find(*l_var_ref);
                                if(i_t != l_cx_map.end())
                                {
                                        l_pv = atoi(i_t->second.c_str());
                                }
                                int32_t l_nv = 0;
                                l_nv = atoi(l_val_ref->c_str());
                                char l_val_str[8];
                                snprintf(l_val_str, 8, "%d", l_pv - l_nv);
                                l_cx_map[*l_var_ref] =  l_val_str;
                                break;
                        }
                        //----------------------------------
                        // default
                        //----------------------------------
                        default:
                        {
                                //NDBG_PRINT("error invalid op\n");
                                break;
                        }
                        }
                        break;
                }
                // -----------------------------------------
                // IP
                // -----------------------------------------
                case ::waflz_pb::sec_action_t_setvar_t_scope_t_IP:
                {
                        // TODO ???
                        continue;
                }
                default:
                {

                }
                }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::process_match(waflz_pb::event** ao_event,
                           const waflz_pb::sec_rule_t& a_rule,
                           rqst_ctx& a_ctx)
{
        if(!ao_event ||
           !a_rule.has_action())
        {
                NDBG_PRINT("missing event or action\n");
                return WAFLZ_STATUS_ERROR;
        }
        const waflz_pb::sec_action_t &l_action = a_rule.action();
        // -------------------------------------------------
        // compare...
        // -------------------------------------------------
        // 1. get "anomaly_score"...
        // 2. get "inbound_anomaly_score_threshold" or "inbound_anomaly_score_level" --> threshold
        // 3. if(l_score >= l_threshold) mark as intercepted...
        // -------------------------------------------------
        cx_map_t::const_iterator i_t;
        int32_t l_anomaly_score = -1;
        // -------------------------------------------------
        // get anomaly score
        // -------------------------------------------------
        i_t = a_ctx.m_cx_tx_map.find("anomaly_score");
        if(i_t == a_ctx.m_cx_tx_map.end())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // TODO -use strntol instead
        // of atoi...
        // -------------------------------------------------
        l_anomaly_score = atoi(i_t->second.c_str());
        // -------------------------------------------------
        // skip if no anomaly score and
        // w/o action or PASS types...
        // -------------------------------------------------
        if((l_anomaly_score <= 0) &&
           (!l_action.has_action_type() ||
            (l_action.action_type() == ::waflz_pb::sec_action_t_action_type_t_PASS)))
        {
                return WAFLZ_STATUS_OK;
        }
#ifdef WAFLZ_NATIVE_ANOMALY_MODE
        // -------------------------------------------------
        // skip logging events not contributing to anomaly
        // action
        // -------------------------------------------------
        if(m_anomaly_score_cur >= l_anomaly_score &&
           l_action.action_type() == waflz_pb::sec_action_t_action_type_t_PASS)
        {
                return WAFLZ_STATUS_OK;
        }
        m_anomaly_score_cur = l_anomaly_score;
#endif
#define _GET_TX_FIELD(_str, _val) do { \
        i_t = a_ctx.m_cx_tx_map.find(_str); \
        if(i_t == a_ctx.m_cx_tx_map.end()) { \
                NDBG_PRINT("rule: %s missing tx field: %s.\n", a_rule.ShortDebugString().c_str(), _str);\
                return WAFLZ_STATUS_ERROR; \
        } \
        _val = atoi(i_t->second.c_str()); \
} while(0)
        // -------------------------------------------------
        // *************************************************
        // handling anomaly mode natively...
        // *************************************************
        // -------------------------------------------------
#ifdef WAFLZ_NATIVE_ANOMALY_MODE
        // -------------------------------------------------
        // get field values...
        // -------------------------------------------------
        int32_t l_threshold = -1;
        if(get_owasp_ruleset_version() >= 300)
        {
        _GET_TX_FIELD("inbound_anomaly_score_threshold", l_threshold);
        }
        else
        {
        _GET_TX_FIELD("inbound_anomaly_score_level", l_threshold);
        }
        //NDBG_PRINT("%sl_anomaly_score%s: %d\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_anomaly_score);
        //NDBG_PRINT("%sl_threshold%s:     %d\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_threshold);
        // -------------------------------------------------
        // check threshold
        // -------------------------------------------------
        if(l_anomaly_score >= l_threshold)
        {
                a_ctx.m_intercepted = true;
        }
#else
        // ---------------------------------
        // handle anomaly mode in ruleset
        // ---------------------------------
        UNUSED(l_threshold);
        if(l_action.has_action_type() &&
           (l_action.action_type() == waflz_pb::sec_action_t_action_type_t_DENY))
        {
                a_ctx.m_intercepted = true;
        }
#endif
        // -------------------------------------------------
        // check for nolog
        // -------------------------------------------------
        if(l_action.has_nolog() &&
           l_action.nolog() &&
           l_action.action_type() == ::waflz_pb::sec_action_t_action_type_t_PASS)
        {
                a_ctx.m_intercepted = false;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // skip events w/o messages
        // -------------------------------------------------
        if(!l_action.has_msg())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // create info...
        // -------------------------------------------------
        waflz_pb::event* l_sub_event = NULL;
        if(!(*ao_event))
        {
                *ao_event = new ::waflz_pb::event();
        }
        //NDBG_PRINT("%sadd_sub_event%s:\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
        l_sub_event = (*ao_event)->add_sub_event();
        // -------------------------------------------------
        // populate info
        // -------------------------------------------------
        // -------------------------------------------------
        // msg
        // -------------------------------------------------
        std::string l_msg;
        macro &l_macro = m_engine.get_macro();
        if(l_macro.has(l_action.msg()))
        {
                int32_t l_s;
                l_s = l_macro(l_msg, l_action.msg(), &a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        if(!l_msg.empty())
        {
                 (*ao_event)->set_rule_msg(l_msg);
                 l_sub_event->set_rule_msg(l_msg);
        }
        else
        {
                if(l_action.has_msg()) { l_sub_event->set_rule_msg(l_action.msg()); }
                (*ao_event)->set_rule_msg(l_action.msg());
        }
        // -------------------------------------------------
        // rule info
        // -------------------------------------------------
        if(l_action.has_id()) { l_sub_event->set_rule_id((uint32_t)atol(l_action.id().c_str())); }
        if(a_rule.operator_().has_type())
        {
                const google::protobuf::EnumValueDescriptor* l_op_desc =
                                        waflz_pb::sec_rule_t_operator_t_type_t_descriptor()->FindValueByNumber(a_rule.operator_().type());
                l_sub_event->set_rule_op_name(l_op_desc->name());
        }
        if(a_rule.operator_().has_value()) { l_sub_event->set_rule_op_param(a_rule.operator_().value()); }
        // -------------------------------------------------
        // tx vars
        // -------------------------------------------------
        int32_t l_sql_injection_score;
        int32_t l_xss_score;
        _GET_TX_FIELD("sql_injection_score", l_sql_injection_score);
        _GET_TX_FIELD("xss_score", l_xss_score);
        l_sub_event->set_total_anomaly_score(l_anomaly_score);
        l_sub_event->set_total_sql_injection_score(l_sql_injection_score);
        l_sub_event->set_total_xss_score(l_xss_score);
        // -------------------------------------------------
        // rule targets
        // -------------------------------------------------
        //NDBG_PRINT("rule matched %s\n", a_rule.DebugString().c_str());
        for(int32_t i_k = 0; i_k < a_rule.variable_size(); ++i_k)
        {
                const waflz_pb::variable_t &l_var = a_rule.variable(i_k);
                const google::protobuf::EnumValueDescriptor* l_var_desc =
                                       waflz_pb::variable_t_type_t_descriptor()->FindValueByNumber(l_var.type());
                waflz_pb::event::var_t *l_mvar = NULL;
                l_mvar = l_sub_event->add_rule_target();
                // -----------------------------------------
                // counting???
                // -----------------------------------------
                if(l_var.has_is_count() &&
                   l_var.is_count())
                {
                        l_mvar->set_is_counting(true);
                }
                // -----------------------------------------
                // no match info
                // -----------------------------------------
                if(l_var.match_size() <= 0)
                {
                        l_mvar->set_name(l_var_desc->name());
                        continue;
                }
                // -----------------------------------------
                // for each match...
                // -----------------------------------------
                for(int32_t i_m = 0; i_m < l_var.match_size(); ++i_m)
                {
                        // ---------------------------------
                        // name
                        // ---------------------------------
                        l_mvar->set_name(l_var_desc->name());
                        // ---------------------------------
                        // value
                        // ---------------------------------
                        const waflz_pb::variable_t_match_t &l_match = l_var.match(i_m);
                        if(!l_match.value().empty())
                        {
                                // -------------------------
                                // fix up string to indicate
                                // is regex
                                // -------------------------
                                std::string l_val = l_match.value();
                                if(l_match.is_regex())
                                {
                                        l_val.insert(0, "/");
                                        l_val += "/";
                                }
                                l_mvar->set_param(l_val);
                        }
                        // ---------------------------------
                        // negated???
                        // ---------------------------------
                        if(l_match.is_negated())
                        {
                                l_mvar->set_is_negated(true);
                        }
                }
        }
        // -------------------------------------------------
        // rule tags
        // -------------------------------------------------
        for(int32_t i_a = 0; i_a < l_action.tag_size(); ++i_a)
        {
                l_sub_event->add_rule_tag(l_action.tag(i_a));
        }
        // -------------------------------------------------
        // intercept status
        // -------------------------------------------------
        l_sub_event->set_rule_intercept_status(403);
        // -------------------------------------------------
        // waf config specifics
        // -------------------------------------------------
        l_sub_event->set_waf_profile_id(m_id);
        l_sub_event->set_waf_profile_name(m_name);
        // -------------------------------------------------
        // check for no log
        // -------------------------------------------------
        if(m_no_log_matched)
        {
                return WAFLZ_STATUS_OK;
        }
#define CAP_LEN(_len) (_len > 1024 ? 1024: _len)
        waflz_pb::event::var_t* l_m_var = NULL;
        // -------------------------------------------------
        // matched var
        // -------------------------------------------------
        l_m_var = l_sub_event->mutable_matched_var();
        l_m_var->set_name(a_ctx.m_cx_matched_var_name);
        if(l_action.sanitisematched())
        {
                l_m_var->set_value("**SANITIZED**");
        }
        else
        {
                l_m_var->set_value(a_ctx.m_cx_matched_var.c_str(), CAP_LEN(a_ctx.m_cx_matched_var.length()));
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::process_phase(waflz_pb::event **ao_event,
                           const directive_list_t &a_dl,
                           const marker_map_t &a_mm,
                           rqst_ctx &a_ctx)
{
        for(directive_list_t::const_iterator i_d = a_dl.begin();
            i_d != a_dl.end();
            ++i_d)
        {
                if(!(*i_d))
                {
                        //NDBG_PRINT("SKIPPING\n");
                        continue;
                }
                // -----------------------------------------
                // marker
                // -----------------------------------------
                const ::waflz_pb::directive_t& l_d = **i_d;
                if(l_d.has_marker())
                {
                        //NDBG_PRINT("%sMARKER%s: %s%s%s\n",
                        //           ANSI_COLOR_BG_RED, ANSI_COLOR_OFF,
                        //           ANSI_COLOR_BG_RED, l_d.marker().c_str(), ANSI_COLOR_OFF);
                        continue;
                }
                // -----------------------------------------
                // action
                // -----------------------------------------
                if(l_d.has_sec_action())
                {
                        const waflz_pb::sec_action_t &l_a = l_d.sec_action();
                        int32_t l_s = process_action_nd(l_a, a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                NDBG_PRINT("error processing rule\n");
                        }
                        continue;
                }
                // -----------------------------------------
                // rule
                // -----------------------------------------
                if(l_d.has_sec_rule())
                {
                        const waflz_pb::sec_rule_t &l_r = l_d.sec_rule();
                        if(!l_r.has_action())
                        {
                                //NDBG_PRINT("error no action for rule: %s\n", l_r.ShortDebugString().c_str());
                                continue;
                        }
                        int32_t l_s;
                        l_s = process_rule(ao_event, l_r, a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                // -----------------------------------------
                // break if intercepted
                // -----------------------------------------
                if(a_ctx.m_intercepted)
                {
                        break;
                }
                // -----------------------------------------
                // handle skip
                // -----------------------------------------
                if(a_ctx.m_skip)
                {
                        //NDBG_PRINT("%sskipping%s...: %d\n", ANSI_COLOR_BG_YELLOW, ANSI_COLOR_OFF, a_ctx.m_skip);
                        while(a_ctx.m_skip &&
                              (i_d != a_dl.end()))
                        {
                                ++i_d;
                                --a_ctx.m_skip;
                        }
                        a_ctx.m_skip = 0;
                }
                else if(a_ctx.m_skip_after)
                {
                        //NDBG_PRINT("%sskipping%s...: %s\n", ANSI_COLOR_BG_YELLOW, ANSI_COLOR_OFF, a_ctx.m_skip_after);
                        marker_map_t::const_iterator i_nd;
                        i_nd = a_mm.find(a_ctx.m_skip_after);
                        if(i_nd != a_mm.end())
                        {
                                i_d = i_nd->second;
                        }
                        a_ctx.m_skip_after = NULL;
                }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t waf::append_rqst_info(waflz_pb::event &ao_event, void *a_ctx)
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
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::process(waflz_pb::event **ao_event, void *a_ctx)
{
        //int32_t l_s = WAFLZ_STATUS_OK;
        if(!m_pb)
        {
                return WAFLZ_STATUS_ERROR;
        }
#ifdef WAFLZ_NATIVE_ANOMALY_MODE
        m_anomaly_score_cur = 0;
#endif
        // -------------------------------------------------
        // get rqst_ctx
        // -------------------------------------------------
        int32_t l_s;
        // get body size max
        uint32_t l_body_size_max = DEFAULT_BODY_SIZE_MAX;
        if(m_pb->has_request_body_in_memory_limit())
        {
                l_body_size_max = m_pb->request_body_in_memory_limit();
        }
        rqst_ctx *l_ctx = new rqst_ctx(l_body_size_max, m_parse_json);
        // -------------------------------------------------
        // *************************************************
        //                 P H A S E  1
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = l_ctx->init_phase_1(a_ctx,
                                  m_il_query,
                                  m_il_header,
                                  m_il_cookie);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                NDBG_PRINT("error init_phase_1\n");
                if(l_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        l_s = process_phase(ao_event,
                            m_compiled_config->m_directive_list_phase_1,
                            m_compiled_config->m_marker_map_phase_1,
                            *l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if(l_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // *************************************************
        //                 P H A S E  2
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = l_ctx->init_phase_2(m_ctype_parser_map, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                NDBG_PRINT("error init_phase_2\n");
                if(l_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        l_s = process_phase(ao_event,
                            m_compiled_config->m_directive_list_phase_2,
                            m_compiled_config->m_marker_map_phase_2,
                            *l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if(l_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check for intercepted...
        // -------------------------------------------------
        if(!l_ctx->m_intercepted)
        {
                if(*ao_event)
                {
                        delete *ao_event;
                        *ao_event = NULL;
                }
                if(l_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_OK;
        }
        if(!*ao_event)
        {
                if(l_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_OK;
        }

        // ---------------------------------
        // add rqst info
        // ---------------------------------
        waflz_pb::event &l_event = **ao_event;
        l_s = append_rqst_info(l_event, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error...\n");
                return WAFLZ_STATUS_ERROR;
        }
        // ---------------------------------
        // add meta
        // ---------------------------------
        // ---------------------------------
        // *********************************
        // handling anomaly mode natively...
        // *********************************
        // ---------------------------------
#ifdef WAFLZ_NATIVE_ANOMALY_MODE
        l_event.set_rule_id(981176);
        const char l_msg_macro[] = "Inbound Anomaly Score Exceeded (Total Score: %{TX.ANOMALY_SCORE}, SQLi=%{TX.SQL_INJECTION_SCORE}, XSS=%{TX.XSS_SCORE}): Last Matched Message: %{tx.msg}";
        std::string l_msg;
        macro *l_macro =  &(m_engine.get_macro());
        l_s = (*l_macro)(l_msg, l_msg_macro, l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        l_event.set_rule_msg(l_msg);
#endif
        l_event.set_waf_profile_id(m_id);
        l_event.set_waf_profile_name(m_name);
        // ---------------------------------
        // add info from last subevent...
        // ---------------------------------
        // TODO -should we???
        //      -seems redundant
        // ---------------------------------
        if(l_event.sub_event_size())
        {
                const ::waflz_pb::event& l_se = l_event.sub_event(l_event.sub_event_size() - 1);
                // -------------------------
                // rule target...
                // -------------------------
                ::waflz_pb::event_var_t* l_ev = l_event.add_rule_target();
                l_ev->set_name("TX");
                l_ev->set_param("ANOMALY_SCORE");
                // -------------------------
                // rule tag...
                // -------------------------
                l_event.add_rule_tag()->assign("OWASP_CRS/ANOMALY/EXCEEDED");
                // -------------------------
                // matched_var...
                // -------------------------
                if(l_se.has_matched_var())
                {
                        l_event.mutable_matched_var()->CopyFrom(l_se.matched_var());
                }
                // -------------------------
                // op
                // -------------------------
                l_event.mutable_rule_op_name()->assign("gt");
                l_event.mutable_rule_op_param()->assign("0");
        }
#define _SET_IF_EXIST(_str, _field) do { \
if(l_ctx->m_cx_tx_map.find(_str) != l_ctx->m_cx_tx_map.end()) \
{ l_event.set_##_field((uint32_t)(strtoul(l_ctx->m_cx_tx_map[_str].c_str(), NULL, 10))); } \
else { l_event.set_##_field(0); } \
} while(0)
        _SET_IF_EXIST("ANOMALY_SCORE", total_anomaly_score);
        _SET_IF_EXIST("SQL_INJECTION_SCORE", total_sql_injection_score);
        _SET_IF_EXIST("XSS_SCORE", total_xss_score);
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_ctx) { delete l_ctx; l_ctx = NULL;}
        return WAFLZ_STATUS_OK;
}
}
