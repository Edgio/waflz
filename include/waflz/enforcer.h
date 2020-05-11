//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    enforcer.h
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
#ifndef _ENFORCER_H_
#define _ENFORCER_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/rl_obj.h"
//: ----------------------------------------------------------------------------
//: fwd Decl's
//: ----------------------------------------------------------------------------
namespace waflz_pb {
class event;
class config;
class enforcement;
}
namespace ns_waflz
{
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
class rqst_ctx;
//: ----------------------------------------------------------------------------
//: enforcer
//: ----------------------------------------------------------------------------
class enforcer: public rl_obj
{
public:
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        enforcer(bool a_case_insensitive_headers = false);
        enforcer(waflz_pb::config *m_pb, bool a_case_insensitive_headers = false);
        ~enforcer();
        int32_t load(const char *a_buf, uint32_t a_buf_len);
        int32_t load(void *a_js);
        int32_t process(const waflz_pb::enforcement** ao_enf, rqst_ctx* a_ctx);
        int32_t merge(waflz_pb::config &ao_cfg);
        void update_start_time(void);
        uint64_t get_total_limits() const { return m_stat_total_limits; }
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // disallow copy/assign
        enforcer(const enforcer &);
        enforcer& operator=(const enforcer &);
        int32_t validate(void);
        uint64_t m_stat_total_limits;
};
}
#endif
