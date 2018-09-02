//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    waf.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    09/30/2015
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
#ifndef _WAF_H
#define _WAF_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/parser.h"
#include <waflz/config_parser.h>
#include "waflz/def.h"
#include <set>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define DEFAULT_BODY_SIZE_MAX (128*1024)
#define WAFLZ_NATIVE_ANOMALY_MODE 1
//: ----------------------------------------------------------------------------
//: fwd decl's -proto
//: ----------------------------------------------------------------------------
namespace waflz_pb {
class sec_config_t;
class sec_rule_t;
class sec_action_t;
class directive_t;
class event;
};
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
class rqst_ctx;
class nms;
class ac;
class byte_range;
class engine;
class regex;
class profile;
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef std::list<regex *> pcre_list_t;
typedef std::list<regex *> regex_list_t;
typedef std::list<ac *> ac_list_t;
typedef std::list<nms *> nms_list_t;
typedef std::list<byte_range *> byte_range_list_t;
typedef std::list<const ::waflz_pb::directive_t *> directive_list_t;
typedef std::map<std::string, directive_list_t::const_iterator> marker_map_t;
typedef std::set<std::string> disabled_rule_id_set_t;
typedef struct _compiled_config {
        // phase 1
        marker_map_t m_marker_map_phase_1;
        directive_list_t m_directive_list_phase_1;
        // phase 2
        marker_map_t m_marker_map_phase_2;
        directive_list_t m_directive_list_phase_2;
        // storage
        regex_list_t m_regex_list;
        ac_list_t m_ac_list;
        nms_list_t m_nms_list;
        byte_range_list_t m_byte_range_list;
        ~_compiled_config();
} compiled_config_t;
//: ----------------------------------------------------------------------------
//: \details: TODO
//: ----------------------------------------------------------------------------
class waf
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        waf(engine &a_engine);
        ~waf();
        int32_t process(waflz_pb::event **ao_event, void *a_ctx);
        int32_t init(profile &a_profile, bool a_leave_tmp_file = false);
        int32_t init(config_parser::format_t a_format, const std::string &a_path, bool a_apply_defaults = false);
        int32_t regex_list_add(const std::string &a_regex, pcre_list_t &a_pcre_list);
        int32_t get_str(std::string &ao_str, config_parser::format_t a_format);
        const char *get_err_msg(void) { return m_err_msg; }
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        void set_id(const std::string &a_id) { m_id = a_id; }
        void set_name(const std::string &a_name) { m_name = a_name; }
        void set_owasp_ruleset_version(uint32_t a_version) { m_owasp_ruleset_version = a_version; }
        void set_parse_json( const bool &a_parse_json) { m_parse_json = a_parse_json; }
        uint32_t get_owasp_ruleset_version(void) { return m_owasp_ruleset_version; }
        // -------------------------------------------------
        // public static methods
        // -------------------------------------------------
        static int32_t append_rqst_info(waflz_pb::event &ao_event, void *a_ctx);
        // TODO -make private!!!
        pcre_list_t m_il_query;
        pcre_list_t m_il_header;
        pcre_list_t m_il_cookie;
private:
        // -------------------------------------------------
        // private types
        // -------------------------------------------------
        typedef std::list<regex *> regex_list_t;
        typedef std::list<ac *> ac_list_t;
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        waf(const waf &);
        waf& operator=(const waf &);
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        int32_t process_phase(waflz_pb::event **ao_event, const directive_list_t &a_dl, const marker_map_t &a_mm, rqst_ctx &a_ctx);
        int32_t process_rule(waflz_pb::event **ao_event, const waflz_pb::sec_rule_t &a_rule, rqst_ctx &a_ctx);
        int32_t process_rule_part(waflz_pb::event **ao_event, bool &ao_match, const waflz_pb::sec_rule_t &a_rule, rqst_ctx &a_ctx);
        int32_t process_action_nd(const waflz_pb::sec_action_t &a_action, rqst_ctx &a_ctx);
        int32_t process_action_dx(const waflz_pb::sec_action_t &a_action, rqst_ctx &a_ctx);
        int32_t process_match(waflz_pb::event **ao_event, const waflz_pb::sec_rule_t &a_rule, rqst_ctx &a_ctx);
        int32_t compile(void);
        int32_t set_defaults(void);
        // -------------------------------------------------
        // protobuf
        // -------------------------------------------------
        waflz_pb::sec_config_t *m_pb;
        // -------------------------------------------------
        // compiled...
        // -------------------------------------------------
        compiled_config_t *m_compiled_config;
        ctype_parser_map_t m_ctype_parser_map;
        // -------------------------------------------------
        // modifications
        // -------------------------------------------------
        directive_list_t m_mx_rule_list;
#ifdef WAFLZ_NATIVE_ANOMALY_MODE
        int32_t m_anomaly_score_cur;
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
        bool m_parse_json;
#endif
        // -------------------------------------------------
        // sharing private fields with engine...
        // -------------------------------------------------
        friend engine;
};
}
#endif
