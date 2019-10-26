//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    scopes.h
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
#ifndef _SCOPES_H_
#define _SCOPES_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "cityhash/city.h"
#include <string>
#include <inttypes.h>
#if defined(__APPLE__) || defined(__darwin__)
    #include <unordered_map>
#else
    #include <tr1/unordered_map>
#endif
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace waflz_pb {
        class enforcement;
        class scope_config;
        class event;
        class scope;
        class op_t;
        class config;
        class limit;
        class condition_group;
}
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
class engine;
class rqst_ctx;
class acl;
class rules;
class profile;
class limit;
class kv_db;
class enforcer;
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
class scopes
{
public:
        // -------------------------------------------------
        // str hash
        // -------------------------------------------------
        struct str_hash
        {
                inline std::size_t operator()(const std::string& a_key) const
                {
                        return CityHash64(a_key.c_str(), a_key.length());
                }
        };
#if defined(__APPLE__) || defined(__darwin__)
        typedef std::unordered_map<std::string, acl*, str_hash> id_acl_map_t;
        typedef std::unordered_map<std::string, rules*, str_hash> id_rules_map_t;
        typedef std::unordered_map<std::string, profile*, str_hash> id_profile_map_t;
        typedef std::unordered_map<std::string, limit*, str_hash> id_limit_map_t;
#else
        typedef std::tr1::unordered_map<std::string, acl*, str_hash> id_acl_map_t;
        typedef std::tr1::unordered_map<std::string, rules*, str_hash> id_rules_map_t;
        typedef std::tr1::unordered_map<std::string, profile*, str_hash> id_profile_map_t;
        typedef std::tr1::unordered_map<std::string, limit*, str_hash> id_limit_map_t;
#endif
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        scopes(engine &a_engine, kv_db &a_kv_db);
        ~scopes();
        const char *get_err_msg(void) { return m_err_msg; }
        const waflz_pb::scope_config *get_pb(void) { return m_pb; }
        std::string& get_id(void) { return m_id; }
        int32_t load(const char *a_buf, uint32_t a_buf_len, const std::string& a_conf_dir_path);
        int32_t load(void *a_js, const std::string& a_conf_dir_path);
        int32_t process(const waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        rqst_ctx **ao_rqst_ctx);
        bool get_enf_limit(void) { return m_enf_limit;}
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        //DISALLOW_DEFAULT_CTOR(scopes);
        // disallow copy/assign
        scopes(const scopes &);
        scopes& operator=(const scopes &);
        int32_t load_parts(waflz_pb::scope& a_scope, const std::string& a_conf_dir_path);
        int32_t validate(void);
        int32_t add_exceed_limit(waflz_pb::config **ao_cfg,
                                 const waflz_pb::limit& a_limit,
                                 const waflz_pb::condition_group *a_condition_group,
                                 const waflz_pb::enforcement &a_action,
                                 rqst_ctx *a_ctx);
        int32_t process(const waflz_pb::enforcement** ao_enf,
                        waflz_pb::event** ao_audit_event,
                        waflz_pb::event** ao_prod_event,
                        const ::waflz_pb::scope& a_scope,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        rqst_ctx **ao_rqst_ctx);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        waflz_pb::scope_config *m_pb;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine &m_engine;
        kv_db &m_db;
        // properties
        std::string m_id;
        std::string m_cust_id;
        // -------------------------------------------------
        // parts...
        // -------------------------------------------------
        id_acl_map_t m_id_acl_map;
        id_rules_map_t m_id_rules_map;
        id_profile_map_t m_id_profile_map;
        id_limit_map_t m_id_limit_map;
        // -------------------------------------------------
        // enforcements
        // -------------------------------------------------
        enforcer *m_enfx;
        // -------------------------------------------------
        // flag new enforcement
        // -------------------------------------------------
        bool m_enf_limit;
};
//: ----------------------------------------------------------------------------
//: run operation
//: ----------------------------------------------------------------------------
int32_t rl_run_op(bool &ao_matched,
                  const waflz_pb::op_t &a_op,
                  const char *a_data,
                  uint32_t a_data_len,
                  bool a_case_insensitive);
//: ----------------------------------------------------------------------------
//: check scope
//: ----------------------------------------------------------------------------
int32_t in_scope(bool &ao_match,
                 const waflz_pb::scope &a_scope,
                 rqst_ctx *a_ctx);
//: ----------------------------------------------------------------------------
//: get/convert enforcement
//: ----------------------------------------------------------------------------
int32_t compile_action(waflz_pb::enforcement& ao_axn, char* ao_err_msg);
}
#endif
