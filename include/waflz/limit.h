//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    limit.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    09/09/2019
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
#ifndef _LIMIT_H_
#define _LIMIT_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/rl_obj.h"
#include <set>
//: ----------------------------------------------------------------------------
//: fwd Decl's
//: ----------------------------------------------------------------------------
namespace waflz_pb {
        class condition_group;
        class limit;
}
namespace ns_waflz
{
//: ----------------------------------------------------------------------------
//: fwd Decl's
//: ----------------------------------------------------------------------------
class kv_db;
class regex;
//: ----------------------------------------------------------------------------
//: config
//: ----------------------------------------------------------------------------
class limit: public rl_obj
{
public:
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        limit(kv_db &a_db, bool a_case_insensitive_headers = false);
        ~limit();
        int32_t load(const char *a_buf, uint32_t a_buf_len);
        int32_t load(void *a_js);
        const std::string& get_last_modified_date();
        int32_t process(bool &ao_exceeds,
                        const waflz_pb::condition_group** ao_cg,
                        const std::string& a_scope_id,
                        rqst_ctx* a_ctx);
        const char *get_err_msg(void) { return m_err_msg; }
        waflz_pb::limit *get_pb(void) { return m_pb; }
        const std::string& get_id(void) { return m_id; }
        const std::string& get_cust_id(void) { return m_cust_id; }
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // disallow copy/assign
        limit(const limit &);
        limit& operator=(const limit &);
        int32_t init(void);
        int32_t incr_key(bool &ao_exceeds, const std::string& a_scope_id, rqst_ctx* a_ctx);
        int32_t get_key(char* ao_key, const std::string& a_scope_id, rqst_ctx *a_ctx);
        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        bool m_init;
        waflz_pb::limit *m_pb;
        kv_db &m_db;
        std::string m_id;
        std::string m_cust_id;
};
}
#endif
