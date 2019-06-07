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
#include <string>
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace waflz_pb {
        class enforcement;
        class scope_config;
        class event;
}
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
class geoip2_mmdb;
class engine;
class rqst_ctx;
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
        // Public methods
        // -------------------------------------------------
        scopes(engine &a_engine, geoip2_mmdb &a_geoip2_mmdb);
        ~scopes();
        const char *get_err_msg(void) { return m_err_msg; }
        const waflz_pb::scope_config *get_pb(void) { return m_pb; }
        int32_t load_config(const char *a_buf,
                            uint32_t a_buf_len);
        int32_t load_config(void *a_js);
        int32_t process(const waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        rqst_ctx **ao_rqst_ctx);
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        //DISALLOW_DEFAULT_CTOR(scopes);
        // disallow copy/assign
        scopes(const scopes &);
        scopes& operator=(const scopes &);
        int32_t validate(void);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        waflz_pb::scope_config *m_pb;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine &m_engine;
        // -------------------------------------------------
        // *************************************************
        // geoip2 support
        // *************************************************
        // -------------------------------------------------
        geoip2_mmdb &m_geoip2_mmdb;
};
}
#endif
