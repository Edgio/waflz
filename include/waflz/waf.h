//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _WAF_H
#define _WAF_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/parser.h"
#include <waflz/config_parser.h>
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "waflz/resp_ctx.h"
#include <set>
#include <pcrecpp.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define WAFLZ_NATIVE_ANOMALY_MODE 1
#define _WAFLZ_PCRE_MATCH_LIMIT 1000
#define _WAFLZ_PCRE_MATCH_LIMIT_RECURSION 1000
//! ----------------------------------------------------------------------------
//! fwd decl's -proto
//! ----------------------------------------------------------------------------
namespace waflz_pb {
class sec_config_t;
class sec_rule_t;
class sec_action_t;
class directive_t;
class event;
};
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class rqst_ctx;
class nms;
class ac;
class byte_range;
class engine;
class regex;
class profile;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::list<regex *> regex_list_t;
typedef std::list<ac *> ac_list_t;
typedef std::list<nms *> nms_list_t;
typedef std::list<byte_range *> byte_range_list_t;
typedef std::list<const ::waflz_pb::directive_t *> directive_list_t;
typedef std::map<std::string, directive_list_t::const_iterator> marker_map_t;
typedef std::map<std::string, waflz_pb::enforcement*> action_map_t;
typedef std::set<std::string> disabled_rule_id_set_t;
typedef struct _compiled_config {
        // phase 1
        marker_map_t m_marker_map_phase_1;
        directive_list_t m_directive_list_phase_1;
        // phase 2
        marker_map_t m_marker_map_phase_2;
        directive_list_t m_directive_list_phase_2;
         // phase 3
        marker_map_t m_marker_map_phase_3;
        directive_list_t m_directive_list_phase_3;
         // phase 4
        marker_map_t m_marker_map_phase_4;
        directive_list_t m_directive_list_phase_4;
        // storage
        regex_list_t m_regex_list;
        ac_list_t m_ac_list;
        nms_list_t m_nms_list;
        byte_range_list_t m_byte_range_list;
        _compiled_config():
                m_marker_map_phase_1(),
                m_directive_list_phase_1(),
                m_marker_map_phase_2(),
                m_directive_list_phase_2(),
                m_marker_map_phase_3(),
                m_directive_list_phase_3(),
                m_marker_map_phase_4(),
                m_directive_list_phase_4(),
                m_regex_list(),
                m_ac_list(),
                m_nms_list(),
                m_byte_range_list()
        {}
        ~_compiled_config();
} compiled_config_t;
	typedef struct _scrubber
	{
		std::string m_match_var_type;   // eg REQUEST_COOKIES
		bool m_match_var_name_set;      // eg true
		pcrecpp::RE m_match_var_name;   // eg AV894Kt2TSumQQrJwe-8mzmyREO.*
		pcrecpp::RE m_search;           // eg S23|A23.*
		std::string m_replace;          // eg Redacted
		_scrubber(const std::string &a_search, const std::string &a_replace):
			m_match_var_type(),
			m_match_var_name_set(false),
			m_match_var_name(""),
			m_search(a_search,
				 pcrecpp::RE_Options()
				 .set_multiline(true)
				 .set_dotall(true)
				 .set_match_limit(_WAFLZ_PCRE_MATCH_LIMIT)
				 .set_match_limit_recursion(_WAFLZ_PCRE_MATCH_LIMIT_RECURSION)),
			m_replace(a_replace)
		{}
		~_scrubber(){}
	} scrubber_t;
//! ----------------------------------------------------------------------------
//! \details: TODO
//! ----------------------------------------------------------------------------
class waf
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        waf(engine &a_engine);
        ~waf();
        int32_t process(waflz_pb::event **ao_event, void *a_ctx, rqst_ctx **ao_rqst_ctx = NULL, bool a_custom_rules = false);
        int32_t process_response(waflz_pb::event **ao_event, void *a_ctx, resp_ctx **ao_resp_ctx = NULL, bool a_custom_rules = false);
        int32_t init(profile &a_profile);
        int32_t init(config_parser::format_t a_format, const std::string &a_path, bool a_apply_defaults = false, bool a_custom_rules = false);
        int32_t init(void* a_js, bool a_apply_defaults = false, bool a_custom_rules = false);
        int32_t get_str(std::string &ao_str, config_parser::format_t a_format);
        const char *get_err_msg(void) { return m_err_msg; }
        waflz_pb::sec_config_t* get_pb(void) { return m_pb; }
        const std::string& get_id(void) { return m_id; }
        const std::string& get_cust_id(void) { return m_cust_id; }
        const std::string& get_name(void) { return m_name; }
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        void set_id(const std::string &a_id) { m_id = a_id; }
        void set_name(const std::string &a_name) { m_name = a_name; }
        void set_cust_id(const std::string& a_cust_id) {m_cust_id = a_cust_id; }
        void set_paranoia_level(uint32_t a_paranoia_level) { m_paranoia_level = a_paranoia_level; }
        void set_parse_xml( const bool &a_parse_xml) { m_parse_xml = a_parse_xml; }
        void set_parse_json( const bool &a_parse_json) { m_parse_json = a_parse_json; }
        void set_no_log_matched( const bool &a_no_log_matched) { m_no_log_matched = a_no_log_matched; }
	void add_log_scrubber(const scrubber_t &a_scrubber) { m_log_scrubber.push_back(a_scrubber); }
        uint32_t get_paranoia_level(void) { return m_paranoia_level; }
        bool get_parse_xml(void) { return m_parse_xml; }
        bool get_parse_json(void) { return m_parse_json; }
        uint32_t get_request_body_in_memory_limit(void);
private:
        // -------------------------------------------------
        // private types
        // -------------------------------------------------
        typedef std::list<ac *> ac_list_t;
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        waf(const waf &);
        waf& operator=(const waf &);
        // -------------------------------------------------
        // process request
        // -------------------------------------------------
        int32_t process_phase(waflz_pb::event **ao_event, const directive_list_t &a_dl, const marker_map_t &a_mm, rqst_ctx &a_ctx);
        int32_t process_rule(waflz_pb::event **ao_event, const waflz_pb::sec_rule_t &a_rule, rqst_ctx &a_ctx);
        int32_t process_rule_part(waflz_pb::event **ao_event, bool &ao_match, const waflz_pb::sec_rule_t &a_rule, rqst_ctx &a_ctx);
        int32_t process_action_nd(const waflz_pb::sec_action_t &a_action, rqst_ctx &a_ctx);
        int32_t process_match(waflz_pb::event **ao_event, const waflz_pb::sec_rule_t &a_rule, rqst_ctx &a_ctx);
        // -------------------------------------------------
        // process response
        // -------------------------------------------------
        int32_t process_resp_phase(waflz_pb::event **ao_event, const directive_list_t &a_dl, const marker_map_t &a_mm, resp_ctx &a_ctx);
        int32_t process_resp_rule(waflz_pb::event **ao_event, const waflz_pb::sec_rule_t &a_rule, resp_ctx &a_ctx);
        int32_t process_resp_rule_part(waflz_pb::event **ao_event, bool &ao_match, const waflz_pb::sec_rule_t &a_rule, resp_ctx &a_ctx);
        int32_t process_resp_action_nd(const waflz_pb::sec_action_t &a_action, resp_ctx &a_ctx);
        int32_t process_resp_match(waflz_pb::event **ao_event, const waflz_pb::sec_rule_t &a_rule, resp_ctx &a_ctx);
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        int32_t compile(void);
        int32_t set_defaults(bool a_custom_rules);
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
        std::string m_cust_id;
        std::string m_name;
        std::string m_ruleset_dir;
        uint32_t m_paranoia_level;
        bool m_no_log_matched;
	std::list <scrubber_t> m_log_scrubber;
        bool m_parse_xml;
        bool m_parse_json;
#endif
        // -------------------------------------------------
        // sharing private fields with engine...
        // -------------------------------------------------
        friend engine;
};
}
#endif
