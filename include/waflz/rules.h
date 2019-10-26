//: ----------------------------------------------------------------------------
//: Copyright (C) 2019 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    rules.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    10/01/2019
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
#ifndef _RULES_H_
#define _RULES_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include <string>
#include <list>
#include <set>
#include <strings.h>
#include <map>
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace waflz_pb {
class enforcement;
class profile;
class event;
class request_info;
class acl;
}
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
class engine;
class waf;
class rqst_ctx;
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
class rules
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        rules(engine &a_engine);
        ~rules();
        int32_t process(waflz_pb::event **ao_event, void *a_ctx, rqst_ctx **ao_rqst_ctx = NULL);
        int32_t load_file(const char *a_buf, uint32_t a_buf_len);
        //: ------------------------------------------------
        //:               G E T T E R S
        //: ------------------------------------------------
        //: ------------------------------------------------
        //: \details Get last error message string
        //: \return  last error message (in buffer)
        //: ------------------------------------------------
        const char *get_err_msg(void) { return m_err_msg; }
        waf *get_waf(void) { return m_waf; }
        const std::string &get_id(void) { return m_id; }
        const std::string &get_name(void) { return m_name; }
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        //DISALLOW_DEFAULT_CTOR(profile);
        // disallow copy/assign
        rules(const rules &);
        rules& operator=(const rules &);
        int32_t init(void);
        int32_t validate(void);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine &m_engine;
        // -------------------------------------------------
        // engines...
        // -------------------------------------------------
        waf *m_waf;
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        std::string m_id;
        std::string m_name;
};
}
#endif
