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

//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#ifdef __cplusplus
#include <string>
#include <list>
#include <set>
#include <strings.h>
#include <map>
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#endif
#ifndef _PROFILE_H_
#define _PROFILE_H_
#ifndef __cplusplus
typedef struct profile_t profile;
typedef struct engine_t engine;
typedef struct geoip2_mmdb_t geoip2_mmdb;
typedef struct rqst_ctx_t rqst_ctx;
#endif

//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
#ifdef __cplusplus
namespace waflz_pb {
class enforcement;
class profile;
class event;
class request_info;
class acl;
}
#endif
#ifdef __cplusplus
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
class engine;
class waf;
class acl;
class geoip2_mmdb;

class rqst_ctx;
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------

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
        int32_t process(waflz_pb::event **ao_event, void *a_ctx, const rqst_ctx_callbacks *a_callbacks, rqst_ctx **ao_rqst_ctx = NULL);
        int32_t process_request_plugin(char **ao_event, void *a_ctx, rqst_ctx **ao_rqst_ctx);
        int32_t process_part(waflz_pb::event **ao_event, void *a_ctx, part_mk_t a_part_mk, const rqst_ctx_callbacks *a_callbacks, rqst_ctx **ao_rqst_ctx = NULL);
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
        const std::string &get_ruleset_dir(void) { return m_ruleset_dir; }
        uint16_t get_action(void) { return m_action; }
        void set_pb(waflz_pb::profile *a_pb);
        void set_ruleset_dir(std::string a_ruleset_dir) { m_ruleset_dir = a_ruleset_dir; }
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
        // private types
        // -------------------------------------------------
        typedef std::list<regex *> regex_list_t;
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        //DISALLOW_DEFAULT_CTOR(profile);
        // disallow copy/assign
        profile(const profile &);
        profile& operator=(const profile &);
        int32_t regex_list_add(const std::string &a_regex, pcre_list_t &a_pcre_list);
        int32_t init(void);
        int32_t validate(void);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        waflz_pb::profile *m_pb;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine &m_engine;
        geoip2_mmdb &m_geoip2_mmdb;
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
        std::string m_ruleset_dir;
        uint16_t m_action;
        bool m_leave_compiled_file;
        uint32_t m_owasp_ruleset_version;
        uint32_t m_paranoia_level;
        pcre_list_t m_il_query;
        pcre_list_t m_il_header;
        pcre_list_t m_il_cookie;
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
#endif

#ifdef __cplusplus
extern "C" {
#endif

profile *create_profile(engine *a_engine, geoip2_mmdb *a_geoip2_mmdb);
int32_t load_config(profile *a_profile, const char *a_buf, uint32_t a_len);
int32_t set_ruleset(profile *a_profile, char *a_ruleset_dir);
int32_t process_request(profile *a_profile, void *ao_rqst_ctx, rqst_ctx *a_rqst_ctx, char **a_event);
int32_t cleanup_profile(profile *a_profile);
#ifdef __cplusplus
}

} // namespace waflz
#endif
#endif // Header