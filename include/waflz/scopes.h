//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _SCOPES_H_
#define _SCOPES_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
#include "waflz/def.h"
#include "waflz/city.h"
#include "waflz/rqst_ctx.h"
#include "waflz/resp_ctx.h"
#include <string>
#include <inttypes.h>
#include <list>
#include <unordered_set>
#if defined(__APPLE__) || defined(__darwin__)
    #include <unordered_map>
#else
    #include <tr1/unordered_map>
#endif
#endif
#ifndef __cplusplus
#include "waflz/rqst_ctx.h"
typedef struct engine_t engine;
typedef struct scopes_t scopes;
typedef struct kv_db_t kv_db;
typedef struct rqst_ctx_t rqst_ctx;
#endif
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
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
#endif
#ifdef __cplusplus
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class engine;
class rqst_ctx;
class acl;
class rules;
class bots;
class profile;
class limit;
class kv_db;
class enforcer;
class challenge;
class regex;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
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
        // ----------------------------------------------------------------------------
        // types
        // ----------------------------------------------------------------------------
        typedef std::unordered_set<data_t, data_t_hash, data_comp_unordered> data_set_t;
        typedef std::unordered_set<data_t, data_t_case_hash, data_case_i_comp_unordered> data_case_i_set_t;
        // ----------------------------------------------------------------------------
        // compiled operators
        // ----------------------------------------------------------------------------
        typedef std::list<regex *> regex_list_t;
        typedef std::list<data_set_t *> data_set_list_t;
        typedef std::list<data_case_i_set_t *> data_case_i_set_list_t;
#if defined(__APPLE__) || defined(__darwin__)
        typedef std::unordered_map<std::string, acl*, str_hash> id_acl_map_t;
        typedef std::unordered_map<std::string, rules*, str_hash> id_rules_map_t;
        typedef std::unordered_map<std::string, profile*, str_hash> id_profile_map_t;
        typedef std::unordered_map<std::string, limit*, str_hash> id_limit_map_t;
        typedef std::unordered_map<std::string, bots*, str_hash> id_bots_map_t;
#else
        typedef std::tr1::unordered_map<std::string, acl*, str_hash> id_acl_map_t;
        typedef std::tr1::unordered_map<std::string, rules*, str_hash> id_rules_map_t;
        typedef std::tr1::unordered_map<std::string, profile*, str_hash> id_profile_map_t;
        typedef std::tr1::unordered_map<std::string, limit*, str_hash> id_limit_map_t;
        typedef std::tr1::unordered_map<std::string, bots*, str_hash> id_bots_map_t;
#endif
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        scopes(engine &a_engine, kv_db &a_kv_db, challenge& a_challenge);
        ~scopes();
        const char *get_err_msg(void) { return m_err_msg; }
        const waflz_pb::scope_config *get_pb(void) { return m_pb; }
        std::string& get_id(void) { return m_id; }
        std::string& get_cust_id(void) { return m_cust_id; }
        std::string& get_account_type(void) { return m_account_type; }
        std::string &get_partner_id(void) { return m_partner_id; }
        std::string &get_name(void) { return m_name; }
        int32_t load(const char *a_buf, uint32_t a_buf_len, const std::string& a_conf_dir_path);
        int32_t load(void *a_js, const std::string& a_conf_dir_path);
        int32_t load_acl(ns_waflz::acl* a_acl);
        int32_t load_rules(ns_waflz::rules* a_rules);
        int32_t load_bots(ns_waflz::bots* a_bots);
        int32_t load_profile(ns_waflz::profile* a_profile);
        int32_t load_limit(ns_waflz::limit* a_limit);
        int32_t process(const waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        const rqst_ctx_callbacks *a_callbacks,
                        rqst_ctx **ao_rqst_ctx);
        int32_t process_request_plugin(void **ao_enf, size_t *ao_enf_len,
                                       void **ao_audit_event, size_t *ao_audit_event_len,
                                       void **ao_prod_event, size_t *ao_prod_event_len,
                                       void *a_ctx, const rqst_ctx_callbacks *a_callbacks,
                                       rqst_ctx **ao_rqst_ctx);

        int32_t process_response(
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        const resp_ctx_callbacks *a_cb,
                        resp_ctx **ao_resp_ctx);
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        //DISALLOW_DEFAULT_CTOR(scopes);
        // disallow copy/assign
        scopes(const scopes &);
        scopes& operator=(const scopes &);
        int32_t load_parts(waflz_pb::scope& a_scope, const std::string& a_conf_dir_path);
        int32_t compile(const std::string& a_conf_dir_path);
        int32_t compile_op(::waflz_pb::op_t& ao_op);
        int32_t add_exceed_limit(waflz_pb::config **ao_cfg,
                                 const waflz_pb::limit& a_limit,
                                 const waflz_pb::condition_group *a_condition_group,
                                 const waflz_pb::enforcement &a_action,
                                 const ::waflz_pb::scope& a_scope,
                                 rqst_ctx *a_ctx);
        int32_t process(const waflz_pb::enforcement** ao_enf,
                        waflz_pb::event** ao_audit_event,
                        waflz_pb::event** ao_prod_event,
                        const ::waflz_pb::scope& a_scope,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        rqst_ctx **ao_rqst_ctx);

        int32_t process_response(/*const waflz_pb::enforcement** ao_enf,
                        waflz_pb::event** ao_audit_event,
                        waflz_pb::event** ao_prod_event,
                        const ::waflz_pb::scope& a_scope,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        resp_ctx **ao_resp_ctx*/);
        bool compare_dates(const char* a_loaded_date, const char* a_new_date);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        waflz_pb::scope_config *m_pb;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine &m_engine;
        kv_db &m_db;
        regex_list_t m_regex_list;
        data_set_list_t m_data_set_list;
        data_case_i_set_list_t m_data_case_i_set_list;
        // properties
        std::string m_id;
        std::string m_cust_id;
        std::string m_account_type;
        std::string m_partner_id;
        std::string m_name;
        // -------------------------------------------------
        // parts...
        // -------------------------------------------------
        id_acl_map_t m_id_acl_map;
        id_rules_map_t m_id_rules_map;
        id_profile_map_t m_id_profile_map;
        id_limit_map_t m_id_limit_map;
        id_bots_map_t m_id_bots_map;
        // -------------------------------------------------
        // enforcements
        // -------------------------------------------------
        enforcer *m_enfx;
        // -------------------------------------------------
        // bot challenge
        // -------------------------------------------------
        challenge& m_challenge;
};
//! ----------------------------------------------------------------------------
//! run operation
//! ----------------------------------------------------------------------------
int32_t rl_run_op(bool &ao_matched,
                  const waflz_pb::op_t &a_op,
                  const char *a_data,
                  uint32_t a_data_len,
                  bool a_case_insensitive);
//! ----------------------------------------------------------------------------
//! check scope
//! ----------------------------------------------------------------------------
int32_t in_scope(bool &ao_match,
                 const waflz_pb::scope &a_scope,
                 rqst_ctx *a_ctx);
//! ----------------------------------------------------------------------------
//! get/convert enforcement
//! ----------------------------------------------------------------------------
int32_t compile_action(waflz_pb::enforcement& ao_axn, char* ao_err_msg);
#endif
#ifdef __cplusplus
extern "C" {
#endif
scopes *create_scopes(engine *a_engine, kv_db* a_db);
int32_t load_config(scopes *a_scope, const char *a_buf,
                    uint32_t a_len, const char *a_conf_dir);
int32_t process_waflz(void **ao_enf, size_t *ao_enf_len,
                      void **ao_audit_event, size_t *ao_audit_event_len,
                      void **ao_prod_event, size_t *ao_prod_event_len,
                      scopes *a_scope, void *a_ctx,
                      const rqst_ctx_callbacks *a_callbacks, rqst_ctx **a_rqst_ctx);
int32_t cleanup_scopes(scopes *a_scopes);
const char *get_waflz_error_msg(scopes *a_scopes);
#ifdef __cplusplus
}
} // namespace waflz
#endif
#endif
