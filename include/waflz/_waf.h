//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    _waf.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    04/04/2018
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
#ifndef __WAF_H
#define __WAF_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include <waflz/config_parser.h>
#include <stdint.h>
#include <string>
#include <list>
//: ----------------------------------------------------------------------------
//: fwd decl's -proto
//: ----------------------------------------------------------------------------
namespace waflz_pb {
class event;
};

namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
class engine;
class regex;
class profile;
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef std::list<regex *> pcre_list_t;
//: ----------------------------------------------------------------------------
//: _waf abstract base class
//: ----------------------------------------------------------------------------
class _waf
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        _waf(engine &a_engine);
        virtual ~_waf();
        virtual int32_t init(profile &a_profile, bool a_leave_tmp_file = false) = 0;
        virtual int32_t init(config_parser::format_t a_format, const std::string &a_path, bool a_apply_defaults = false) = 0;
        virtual int32_t process(waflz_pb::event **ao_event, void *a_ctx) = 0;
        int32_t regex_list_add(const std::string &a_regex, pcre_list_t &a_pcre_list);
        const char *get_err_msg(void) { return m_err_msg; }
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        void set_id(const std::string &a_id) { m_id = a_id; }
        void set_name(const std::string &a_name) { m_name = a_name; }
        void set_owasp_ruleset_version(uint32_t a_version) { m_owasp_ruleset_version = a_version; }
        uint32_t get_owasp_ruleset_version(void) { return m_owasp_ruleset_version; }
        // -------------------------------------------------
        // public static methods
        // -------------------------------------------------
        static int32_t append_rqst_info(waflz_pb::event &ao_event, void *a_ctx);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        // TODO -make private!!!
        pcre_list_t m_il_query;
        pcre_list_t m_il_header;
        pcre_list_t m_il_cookie;
protected:
        // -------------------------------------------------
        // protected members
        // -------------------------------------------------
        bool m_is_initd;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine &m_engine;
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        std::string m_id;
        std::string m_name;
        uint32_t m_owasp_ruleset_version;
        bool m_no_log_matched;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        _waf(const _waf &);
        _waf& operator=(const _waf &);
};
}
#endif
