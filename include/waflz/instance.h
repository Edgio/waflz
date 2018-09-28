//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    instance.h
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
#ifndef _INSTANCE_H_
#define _INSTANCE_H_
//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include <string>
#include <list>
//: ----------------------------------------------------------------------------
//: Fwd Decl's
//: ----------------------------------------------------------------------------
namespace waflz_pb {
        class enforcement;
        class instance;
        class profile;
}
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
class profile;
class geoip2_mmdb;
class engine;
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef std::list <std::string> str_list_t;
typedef std::list <waflz_pb::enforcement *> enforcement_list_t;
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
class instance
{
public:
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        instance(engine &a_engine, geoip2_mmdb &a_geoip2_mmdb);
        ~instance();
        //: ------------------------------------------------
        //:               G E T T E R S
        //: ------------------------------------------------
        //: ------------------------------------------------
        //: \brief   get error message
        //: \details Get last error message string
        //: \return  last error message (in buffer)
        //: ------------------------------------------------
        const char *get_err_msg(void) { return m_err_msg; }
        const waflz_pb::instance *get_pb(void) { return m_pb; }
        const std::string &get_id(void) { return m_id; }
        const std::string &get_name(void) { return m_name; }
        const std::string &get_customer_id(void) { return m_customer_id; }
        //: ------------------------------------------------
        //: \brief   get the audit settings values
        //: \details The returned pointer is only valid as long as waf_config
        //:          object is alive
        //: \return  The class representing audit settings on success
        //: ------------------------------------------------
        inline profile* get_audit_profile() { return m_profile_audit; }
        //: ------------------------------------------------
        //: \brief   get the prod settings values
        //: \details The returned pointer is only valid as long as waf_config
        //:          object is alive
        //: \return  The class representing prod settings on success
        //:          NULL is compiler hasn't been validated yet
        //: ------------------------------------------------
        inline profile* get_prod_profile() { return m_profile_prod; }
        enforcement_list_t &get_mutable_prod_enfx_list(void);
        int32_t load_config(const char *a_buf,
                            uint32_t a_buf_len,
                            bool a_leave_compiled_file = false);
        int32_t load_config(void *a_js,
                            bool a_leave_compiled_file = false);
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        //DISALLOW_DEFAULT_CTOR(instance);
        // disallow copy/assign
        instance(const instance &);
        instance& operator=(const instance &);
        int32_t validate(void);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        waflz_pb::instance *m_pb;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine &m_engine;
        // properties
        std::string m_id;
        std::string m_name;
        std::string m_customer_id;
        profile *m_profile_audit;
        profile *m_profile_prod;
        bool m_leave_compiled_file;
        // -------------------------------------------------
        // *************************************************
        // geoip2 support
        // *************************************************
        // -------------------------------------------------
        geoip2_mmdb &m_geoip2_mmdb;
};
}
#endif
