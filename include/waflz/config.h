//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    config.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    11/30/2016
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
#ifndef _CONFIG_H_
#define _CONFIG_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/rl_obj.h"
#include "waflz/challenge.h"
#include <set>
//: ----------------------------------------------------------------------------
//: fwd Decl's
//: ----------------------------------------------------------------------------
namespace waflz_pb {
        class limit;
        class alert;
        class enforcement;
        class enforcer;
}
namespace ns_waflz
{
//: ----------------------------------------------------------------------------
//: fwd Decl's
//: ----------------------------------------------------------------------------
class kv_db;
class regex;
class enforcer;
//: ----------------------------------------------------------------------------
//: config
//: ----------------------------------------------------------------------------
class config: public rl_obj
{
public:
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        config(kv_db &a_db,
               challenge& a_challenge,
               bool a_case_insensitive_headers = false);
        ~config();
        int32_t load(const char *a_buf, uint32_t a_buf_len);
        int32_t load(void *a_js);
        const std::string& get_last_modified_date();
        int32_t process(const waflz_pb::enforcement** ao_enfcmnt,
                        const waflz_pb::limit** ao_limit,
                        rqst_ctx* a_ctx);
        int32_t generate_alert(waflz_pb::alert** ao_alert,
                               rqst_ctx* a_ctx);
        int32_t merge(waflz_pb::config &ao_cfg);
        challenge &get_challenge(void) { return m_challenge;}
        const char *get_err_msg(void) { return m_err_msg; }
private:
        // -------------------------------------------------
        // Private types
        // -------------------------------------------------
        typedef std::set <uint64_t> exceed_key_set_t;
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // disallow copy/assign
        config(const config &);
        config& operator=(const config &);
        int32_t validate(void);
        int32_t load();
        int32_t process_config(waflz_pb::config **ao_cfg,
                               rqst_ctx *a_ctx);
        int32_t process_enfx(const waflz_pb::enforcement** ao_enfcmnt,
                             bool& ao_pass,
                             rqst_ctx* a_ctx);
        int32_t add_limit_with_key(waflz_pb::limit &ao_limit,
                                  uint16_t a_key,
                                  rqst_ctx *a_ctx);
        int32_t add_exceed_limit(waflz_pb::config **ao_cfg,
                                 const std::string &a_cust_id,
                                 const waflz_pb::limit& a_limit,
                                 const waflz_pb::condition_group *a_condition_group,
                                 rqst_ctx *a_ctx);
        int32_t handle_match(waflz_pb::config** ao_cfg,
                             const std::string& a_cust_id,
                             const waflz_pb::limit& a_limit,
                             const waflz_pb::condition_group* a_condition_group,
                             rqst_ctx* a_ctx);
        int32_t get_limit_key_value(char* ao_key,
                                    const std::string& a_cust_id,
                                    const waflz_pb::limit& a_limit,
                                    rqst_ctx *a_ctx);
        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        kv_db &m_db;
        challenge& m_challenge;
        enforcer *m_enfx;
        exceed_key_set_t m_exceed_key_set;
};
}
#endif
