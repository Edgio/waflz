//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    profile.h
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
#ifndef _PROFILE_H_
#define _PROFILE_H_
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
class acl;
class geoip2_mmdb;
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef std::list <std::string> str_list_t;
typedef std::list <waflz_pb::enforcement *> enforcement_list_t;
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
class profile
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        profile(engine &a_engine, geoip2_mmdb &a_geoip2_mmdb);
        ~profile();
        int32_t process(waflz_pb::event **ao_event, void *a_ctx);
        int32_t load_config(const char *a_buf, uint32_t a_buf_len, bool a_leave_compiled_file = false);
        int32_t load_config(const waflz_pb::profile *a_pb, bool a_leave_compiled_file = false);
        //: ------------------------------------------------
        //:               G E T T E R S
        //: ------------------------------------------------
        //: ------------------------------------------------
        //: \details Get last error message string
        //: \return  last error message (in buffer)
        //: ------------------------------------------------
        const char *get_err_msg(void) { return m_err_msg; }
        waflz_pb::profile *get_pb(void) { return m_pb; }
        waf *get_waf(void) { return m_waf; }
        const std::string &get_id(void) { return m_id; }
        const std::string &get_name(void) { return m_name; }
        const std::string &get_resp_header_name(void) { return m_resp_header_name; }
        uint16_t get_action(void) { return m_action; }
        //: ------------------------------------------------
        //:               S E T T E R S
        //: ------------------------------------------------
        //: ------------------------------------------------
        //: TODO
        //: ------------------------------------------------
        void set_pb(waflz_pb::profile *a_pb);
        // -------------------------------------------------
        // public static members
        // -------------------------------------------------
        static uint_fast32_t s_next_ec_rule_id;
        static std::string s_ruleset_dir;
        static std::string s_geoip_db;
        static std::string s_geoip_isp_db;
        static std::string s_geoip2_db;
        static std::string s_geoip2_isp_db;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        //DISALLOW_DEFAULT_CTOR(profile);
        // disallow copy/assign
        profile(const profile &);
        profile& operator=(const profile &);
        int32_t init(void);
        int32_t validate(void);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        waflz_pb::profile *m_pb;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine &m_engine;
        // -------------------------------------------------
        // engines...
        // -------------------------------------------------
        acl *m_acl;
        waf *m_waf;
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        std::string m_id;
        std::string m_name;
        std::string m_resp_header_name;
        uint16_t m_action;
        bool m_leave_compiled_file;
        uint32_t m_owasp_ruleset_version;
        // -------------------------------------------------
        // class members
        // -------------------------------------------------
        static const std::string s_default_name;
        // -------------------------------------------------
        // friends
        // -------------------------------------------------
        friend class instance;
        friend class acl;
};
}
#endif
