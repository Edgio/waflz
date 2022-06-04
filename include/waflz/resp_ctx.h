//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    resp_ctx.h
//! \author:  Kanishk Modi
//! \details: Header file for class responsible for processing response headers and body and evaluating them
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _RESP_CTX_H
#define _RESP_CTX_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <waflz/def.h>
#ifdef __cplusplus
#include <waflz/arg.h>
#include <waflz/parser.h>
//#include <waflz/profile.h>
#include <list>
#include <map>
#include <strings.h>
#endif

//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
#ifndef __cplusplus
typedef struct resp_ctx_t resp_ctx;
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
        get_resp_data_cb_t m_get_resp_content_type_list_cb;
        get_resp_data_size_cb_t m_get_resp_content_length_cb;
        get_resp_data_size_cb_t m_get_resp_header_size_cb;
        get_resp_data_w_key_cb_t m_get_resp_header_w_key_cb;
        get_resp_kv_w_idx_cb_t m_get_resp_header_w_idx_cb;
        get_resp_body_data_cb_t m_get_resp_body_str_cb;
}resp_ctx_callbacks;
#ifdef __cplusplus
}
#endif
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
class waf;
//typedef std::map<std::string, std::string, cx_case_i_comp> cx_map_t;
typedef std::map <data_t, data_t, data_case_i_comp> data_map_t;
typedef std::list<data_t> data_list_t;

//! ----------------------------------------------------------------------------
//! resp_ctx
//! ----------------------------------------------------------------------------
class resp_ctx
{
public:
        // -------------------------------------------------
        // callbacks
        // -------------------------------------------------
        // -------------------------------------------------
        // static members
        // -------------------------------------------------
        static uint32_t s_body_arg_len_cap;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        resp_ctx(void *a_ctx,
                 uint32_t a_body_len_max,
                 const resp_ctx_callbacks *a_callbacks,
                 bool a_parse_xml = false,
                 bool a_parse_json = false);
        ~resp_ctx();

        // response header evaluation
        int32_t init_phase_3();

        // response body evaluation
        int32_t init_phase_4(const ctype_parser_map_t &a_ctype_parser_map);
        int32_t reset_phase_3();
        void show(void);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        uint32_t m_an;
        uint64_t m_content_length;
        data_list_t m_content_type_list;
        data_map_t m_header_map;
        const_arg_list_t m_header_list;
        uint32_t m_body_len_max;
        char *m_body_data;
        uint32_t m_body_len;
        uint32_t m_resp_status;
        // -------------------------------------------------
        // body parser
        // -------------------------------------------------
        parser *m_body_parser;
        arg_list_t m_body_arg_list;
        // -------------------------------------------------
        // collections...
        // -------------------------------------------------
        //cx_map_t m_cx_tx_map;
        // -------------------------------------------------
        // state
        // -------------------------------------------------
        bool m_init_phase_3;
        bool m_init_phase_4;
        // -------------------------------------------------
        // response ctx callbacks struct
        // -------------------------------------------------
        const resp_ctx_callbacks *m_callbacks;

private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        resp_ctx(const resp_ctx &);
        resp_ctx& operator=(const resp_ctx &);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        void *m_ctx;
};
#endif
#ifdef __cplusplus
extern "C" {
#endif
resp_ctx *init_resp_ctx(void *a_ctx, const uint32_t a_max_body_len, const resp_ctx_callbacks *a_callbacks, bool a_parse_json);
int32_t resp_ctx_cleanup(resp_ctx *a_resp_ctx);
#ifdef __cplusplus
}
}
#endif
#endif
