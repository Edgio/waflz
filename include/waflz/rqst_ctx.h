//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _RQST_CTX_H
#define _RQST_CTX_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <waflz/def.h>
#ifdef __cplusplus
#include <waflz/arg.h>
#include <waflz/parser.h>
#include <waflz/profile.h>
#include <list>
#include <map>
#include <strings.h>
#endif

//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
#ifndef __cplusplus
typedef struct rqst_ctx_t rqst_ctx;
#endif
#ifdef __cplusplus
namespace waflz_pb {
class event;
}
namespace waflz_pb {
class limit;
class condition_group;
}
namespace ns_waflz {
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
        get_rqst_data_cb_t m_get_rqst_src_addr_cb;
        get_rqst_data_cb_t m_get_rqst_host_cb;
        get_rqst_data_size_cb_t m_get_rqst_port_cb;
        get_rqst_data_cb_t m_get_rqst_scheme_cb;
        get_rqst_data_cb_t m_get_rqst_protocol_cb;
        get_rqst_data_cb_t m_get_rqst_line_cb;
        get_rqst_data_cb_t m_get_rqst_method_cb;
        get_rqst_data_cb_t m_get_rqst_url_cb;
        get_rqst_data_cb_t m_get_rqst_uri_cb;
        get_rqst_data_cb_t m_get_rqst_path_cb;
        get_rqst_data_cb_t m_get_rqst_query_str_cb;
        get_rqst_data_size_cb_t m_get_rqst_header_size_cb;
        get_rqst_data_w_key_cb_t m_get_rqst_header_w_key_cb;
        get_rqst_kv_w_idx_cb_t m_get_rqst_header_w_idx_cb;
        get_rqst_body_data_cb_t m_get_rqst_body_str_cb;
        get_rqst_data_cb_t m_get_rqst_local_addr_cb;
        get_rqst_data_size_cb_t m_get_rqst_canonical_port_cb;
        get_rqst_data_size_cb_t m_get_rqst_apparent_cache_status_cb;
        get_rqst_data_size_cb_t m_get_rqst_bytes_out_cb;
        get_rqst_data_size_cb_t m_get_rqst_bytes_in_cb;
        get_rqst_data_cb_t m_get_rqst_uuid_cb;
        get_rqst_data_size_cb_t m_get_cust_id_cb;
}rqst_ctx_callbacks;
#ifdef __cplusplus
}
#endif
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
class waf;
class geoip2_mmdb;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
struct cx_case_i_comp
{
        bool operator() (const std::string& lhs, const std::string& rhs) const
        {
                return strcasecmp(lhs.c_str(), rhs.c_str()) < 0;
        }
};
typedef std::map<std::string, std::string, cx_case_i_comp> cx_map_t;
typedef std::map <data_t, data_t, data_case_i_comp> data_map_t;
typedef std::list<data_t> data_list_t;
//! ----------------------------------------------------------------------------
//! xpath optimization
//! ----------------------------------------------------------------------------
typedef std::list <const_arg_t> xpath_arg_list_t;
typedef std::map <std::string, xpath_arg_list_t> xpath_cache_map_t;
//! ----------------------------------------------------------------------------
//! rqst_ctx
//! ----------------------------------------------------------------------------
class rqst_ctx
{
public:
        // -------------------------------------------------
        // callbacks
        // -------------------------------------------------
        static get_data_cb_t s_get_bot_ch_prob;
        // -------------------------------------------------
        // static members
        // -------------------------------------------------
        static uint32_t s_body_arg_len_cap;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        rqst_ctx(void *a_ctx,
                 uint32_t a_body_len_max,
                 const rqst_ctx_callbacks *a_callbacks,
                 bool a_parse_xml = false,
                 bool a_parse_json = false);
        ~rqst_ctx();
        int32_t init_phase_1(geoip2_mmdb &a_geoip2_mmdb,
                             const pcre_list_t *a_il_query = NULL,
                             const pcre_list_t *a_il_header = NULL,
                             const pcre_list_t *a_il_cookie = NULL);
        int32_t init_phase_2(const ctype_parser_map_t &a_ctype_parser_map);
        int32_t reset_phase_1();
        int32_t append_rqst_info(waflz_pb::event &ao_event, geoip2_mmdb &a_geoip2_mmdb);
        void show(void);
        // -------------------------------------------------
        // setters
        // -------------------------------------------------
        void set_body_max_len(uint32_t a_body_len_max) { m_body_len_max = a_body_len_max; }
        void set_parse_xml(bool a_parse_xml) { m_parse_xml = a_parse_xml; }
        void set_parse_json(bool a_parse_json) { m_parse_json = a_parse_json; }
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        uint32_t m_an;
        data_t m_src_addr;
        data_t m_local_addr;
        data_t m_host;
        uint32_t m_port;
        data_t m_scheme;
        data_t m_protocol;
        data_t m_line;
        data_t m_method;
        data_t m_url;
        data_t m_uri;
        data_t m_path;
        data_t m_base;
        data_t m_query_str;
        data_t m_file_ext;
        arg_list_t m_query_arg_list;
        arg_list_t m_body_arg_list;
        data_map_t m_header_map;
        const_arg_list_t m_header_list;
        const_arg_list_t m_cookie_list;
        data_map_t m_cookie_map;
        uint32_t m_apparent_cache_status;
        data_list_t m_content_type_list;
        uint32_t m_uri_path_len;
        uint32_t m_body_len_max;
        char *m_body_data;
        uint32_t m_body_len;
        uint64_t m_content_length;
        bool m_parse_xml;
        bool m_parse_json;
        std::string m_cookie_mutated;
        data_t m_req_uuid;
        uint32_t m_bytes_out;
        uint32_t m_bytes_in;
        mutable_data_t m_token;
        uint32_t m_resp_status;
        bool m_signal_enf;
        bool m_log_request;
        // -------------------------------------------------
        // TODO FIX!!! -not thread safe...
        // -------------------------------------------------
        const waflz_pb::limit* m_limit;
        // -------------------------------------------------
        // body parser
        // -------------------------------------------------
        parser *m_body_parser;
        // -------------------------------------------------
        // collections...
        // -------------------------------------------------
        std::string m_cx_matched_var;
        std::string m_cx_matched_var_name;
        data_map_t m_cx_rule_map;
        cx_map_t m_cx_tx_map;
        // -------------------------------------------------
        // state
        // -------------------------------------------------
        bool m_init_phase_1;
        bool m_init_phase_2;
        bool m_intercepted;
        bool m_wl_audit;
        bool m_wl_prod;
        uint32_t m_skip;
        const char * m_skip_after;
        waflz_pb::event *m_event;
        // -------------------------------------------------
        // xpath optimization
        // -------------------------------------------------
        xpath_cache_map_t *m_xpath_cache_map;
        // -------------------------------------------------
        // request ctx callbacks struct
        // -------------------------------------------------
        const rqst_ctx_callbacks *m_callbacks;
        // -------------------------------------------------
        // extensions
        // -------------------------------------------------
        uint32_t m_src_asn;
        // TODO use uint32???
        mutable_data_t m_src_asn_str;
        data_t m_geo_cn2;
        data_t m_src_sd1_iso;
        data_t m_src_sd2_iso;
        bool m_xml_capture_xxe;
        // -------------------------------------------------
        // bot challenge
        // -------------------------------------------------
        std::string m_bot_ch;
        std::string m_bot_js;
        uint32_t m_ans;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        rqst_ctx(const rqst_ctx &);
        rqst_ctx& operator=(const rqst_ctx &);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        void *m_ctx;
};
#endif
#ifdef __cplusplus
extern "C" {
#endif
rqst_ctx *init_rqst_ctx(void *a_ctx, const uint32_t a_max_body_len, const rqst_ctx_callbacks *a_callbacks, bool a_parse_json);
int32_t rqst_ctx_cleanup(rqst_ctx *a_rqst_ctx);
#ifdef __cplusplus
}
}
#endif
#endif
