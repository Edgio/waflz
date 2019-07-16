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
#include "waflz/scopes.h"
#include <string>
#include <unordered_map>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: fwd Decl's
//: ----------------------------------------------------------------------------
class scopes;
//: ----------------------------------------------------------------------------
//: scopes_configs
//: ----------------------------------------------------------------------------
class scopes_configs
{
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
        typedef std::unordered_map<uint64_t, scopes*> cust_id_scopes_map_t;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        int32_t load_scopes_dir(const char *a_dir_path, uint32_t a_dir_path_len);
        int32_t load_scopes_file(const char *a_file_path, uint32_t a_file_path_len);
        int32_t load_scopes(const char *a_buf, uint32_t a_buf_len);
        int32_t process(const waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        uint64_t a_id,
                        rqst_ctx **ao_rqst_ctx);
        scopes* get_scopes(uint64_t a_id);
        scopes* get_first_scopes();
        const char *get_err_msg(void) { return m_err_msg; }
        void set_locking(bool a_enable_locking) { m_enable_locking = a_enable_locking; }
        scopes_configs(engine& a_engine, bool a_enable_locking);
        ~scopes_configs();
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // disallow copy/assign
        scopes_configs(const scopes_configs &);
        scopes_configs& operator=(const scopes_configs &);
        int32_t load(void *a_js);
        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        cust_id_scopes_map_t m_cust_id_scopes_map;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine& m_engine;
        pthread_mutex_t m_mutex;
        bool m_enable_locking;
};
}
#endif
