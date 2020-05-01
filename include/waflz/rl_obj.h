//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    rl_obj.h
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
#ifndef _RL_OBJ_H_
#define _RL_OBJ_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "string.h"
#include <string>
#include <map>
#include <list>
#include <set>
#include <inttypes.h>
//: ----------------------------------------------------------------------------
//: fwd Decl's
//: ----------------------------------------------------------------------------
namespace waflz_pb
{
class enforcer;
class condition_group;
class match;
class op_t;
class limit;
class config;
class condition_target_t;
class scope;
}
namespace ns_waflz
{
//: ----------------------------------------------------------------------------
//: fwd Decl's
//: ----------------------------------------------------------------------------
class regex;
class rqst_ctx;
class nms;
//: ----------------------------------------------------------------------------
//: comparison operators
//: ----------------------------------------------------------------------------
struct data_comp
{
        bool operator()(const data_t& lhs, const data_t& rhs) const
        {
                uint32_t l_len = lhs.m_len > rhs.m_len ? rhs.m_len : lhs.m_len;
                return strncmp(lhs.m_data, rhs.m_data, l_len) < 0;
        }
};
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef std::set<data_t, data_comp> data_set_t;
typedef std::set<data_t, data_case_i_comp> data_case_i_set_t;
//: ----------------------------------------------------------------------------
//: compiled operators
//: ----------------------------------------------------------------------------
typedef std::list<regex *> regex_list_t;
typedef std::list<nms *> nms_list_t;
typedef std::list<data_set_t *> data_set_list_t;
typedef std::list<data_case_i_set_t *> data_case_i_set_list_t;
//: ----------------------------------------------------------------------------
//: rl_obj
//: ----------------------------------------------------------------------------
class rl_obj
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        rl_obj(bool a_case_insensitive_headers);
        virtual ~rl_obj();
        //: ------------------------------------------------
        //:               G E T T E R S
        //: ------------------------------------------------
        //: ------------------------------------------------
        //: \details Get last error message string
        //: \return  last error message (in buffer)
        //: ------------------------------------------------
        const char *get_err_msg(void)
        {
                return m_err_msg;
        }
        waflz_pb::config* get_pb(void) { return m_pb; }
        waflz_pb::config* get_mutable_pb(void) { return m_pb; }
        const std::string &get_customer_id(void);
protected:
        // -------------------------------------------------
        // Protected members
        // -------------------------------------------------
        bool m_init;
        waflz_pb::config *m_pb;
        char m_err_msg[WAFLZ_ERR_LEN];
        // -------------------------------------------------
        // TODO TEMPORARY HACK to support case insensitive
        // comparisons SECC-445.
        // Really need new operators or something
        // -------------------------------------------------
        bool m_lowercase_headers;
        // -------------------------------------------------
        // protected methods
        // -------------------------------------------------
        int32_t compile(void);
        int32_t compile_limit(waflz_pb::limit &ao_limit);
        int32_t process_condition_group(bool &ao_matched,
                                        const waflz_pb::condition_group &a_cg,
                                        rqst_ctx *a_ctx);
        int32_t convertv1(waflz_pb::config& ao_config,
                          const waflz_pb::enforcer& a_enfcr);
        // -------------------------------------------------
        // protected members
        // -------------------------------------------------
        regex_list_t m_regex_list;
        nms_list_t m_nms_list;
        data_set_list_t m_data_set_list;
        data_case_i_set_list_t m_data_case_i_set_list;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        rl_obj(const rl_obj &);
        rl_obj& operator=(const rl_obj &);
        int32_t extract(const char **ao_data,
                        uint32_t &ao_data_len,
                        std::string &ao_buf,
                        const waflz_pb::condition_target_t &a_tgt,
                        rqst_ctx *a_ctx);
        int32_t compile_op(::waflz_pb::op_t& ao_op);
};
//: ----------------------------------------------------------------------------
//: utils
//: ----------------------------------------------------------------------------
int32_t limit_remove(waflz_pb::config &ao_cfg, uint32_t a_off);
int32_t limit_sweep(waflz_pb::config &ao_cfg);
}
#endif
