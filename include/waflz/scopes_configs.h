//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    scopes_configs.h
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
//: ------------------------------------------------------------------------------
#ifndef _SCOPES_CONFIGS_H
#define _SCOPES_CONFIGS_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/limit.h"
#include "waflz/challenge.h"
#include <pthread.h>
#include <string>
#if defined(__APPLE__) || defined(__darwin__)
    #include <unordered_map>
#else
    #include <tr1/unordered_map>
#endif
//: ----------------------------------------------------------------------------
//: fwd Decl's
//: ----------------------------------------------------------------------------
namespace waflz_pb {
        class alert;
}
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: fwd Decl's
//: ----------------------------------------------------------------------------
class scopes;
class kv_db;
//: ----------------------------------------------------------------------------
//: scopes_configs
//: ----------------------------------------------------------------------------
class scopes_configs
{
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
#if defined(__APPLE__) || defined(__darwin__)
        typedef std::unordered_map<uint64_t, scopes*> cust_id_scopes_map_t;
#else
        typedef std::tr1::unordered_map<uint64_t, scopes*> cust_id_scopes_map_t;
#endif
        
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        int32_t load_dir(const char *a_dir_path, uint32_t a_dir_path_len);
        int32_t load_file(const char *a_file_path, uint32_t a_file_path_len);
        int32_t load(const char *a_buf, uint32_t a_buf_len);
        int32_t load_acl(const char* a_buf, uint32_t a_buf_len);
        int32_t load_limit(const char* a_buf, uint32_t a_buf_len);
        int32_t load_rules(const char* a_buf, uint32_t a_buf_len);
        int32_t load_profile(const char* a_buf, uint32_t a_buf_len);
        int32_t process(waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        uint64_t a_id,
                        part_mk_t a_part_mk,
                        rqst_ctx **ao_rqst_ctx);
        bool check_id(uint64_t a_cust_id);
        const char *get_err_msg(void) { return m_err_msg; }
        int32_t generate_alert(waflz_pb::alert** ao_alert, rqst_ctx* a_ctx, uint64_t a_cust_id);
        void set_locking(bool a_enable_locking) { m_enable_locking = a_enable_locking; }
        void set_conf_dir(const std::string& a_conf_dir) { m_conf_dir = a_conf_dir; }
        void get_first_id(uint64_t &ao_id);
        void get_rand_id(uint64_t &ao_id);
        bool id_exists(uint64_t a_id);
        scopes_configs(engine& a_engine, kv_db& a_db, challenge& a_challenge, bool a_enable_locking);
        ~scopes_configs();
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // disallow copy/assign
        scopes_configs(const scopes_configs &);
        scopes_configs& operator=(const scopes_configs &);
        int32_t load(void *a_js);
        scopes* get_scopes(uint64_t a_id);
        int32_t load_acl(void* a_js);
        int32_t load_limit(void* a_js);
        int32_t load_rules(void* a_js);
        int32_t load_profile(void* a_js);
        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        cust_id_scopes_map_t m_cust_id_scopes_map;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine& m_engine;
        kv_db& m_db;
        pthread_mutex_t m_mutex;
        bool m_enable_locking;
        std::string m_conf_dir;
        // -------------------------------------------------
        // bot challenge
        // -------------------------------------------------
        challenge& m_challenge;
};
}
#endif
