//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    resp_ctx.cc
//! \author:  Kanishk Modi
//! \details: source file for class responsible for processing response headers and body and evaluating them
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "event.pb.h"
#include "waflz/resp_ctx.h"
#include "waflz/string_util.h"
#include "core/decode.h"
//#include "parser/parser_url_encoded.h"
#include "parser/parser_xml.h"
#include "parser/parser_json.h"
#include <stdlib.h>
#include <string.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _DEFAULT_BODY_ARG_LEN_CAP 4096
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------

namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! static
//! ----------------------------------------------------------------------------
//uint32_t resp_ctx::s_body_arg_len_cap = _DEFAULT_BODY_ARG_LEN_CAP;

//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
resp_ctx::resp_ctx(void *a_ctx,
                   uint32_t a_body_len_max,
                   const resp_ctx_callbacks *a_callbacks):
        m_an(),
        m_host(),
        m_uri(),
        m_uri_path_len(0),
        m_content_length(0),
        m_content_type_list(),
        m_header_map(),
        m_header_list(),
        m_body_len_max(a_body_len_max),
        m_body_data(NULL),
        m_body_len(0),
        m_resp_status(0),
        m_intercepted(false),
        m_body_parser(),
        m_body_arg_list(),
        // -------------------------------------------------
        // collections
        // -------------------------------------------------
        m_cx_matched_var(),
        m_cx_matched_var_name(),
        m_cx_rule_map(),
        m_cx_tx_map(),
        // -------------------------------------------------
        // state
        // -------------------------------------------------
        m_init_phase_3(false),
        m_init_phase_4(false),
        m_skip(0),
        m_skip_after(NULL),
        m_callbacks(a_callbacks),
        m_ctx(a_ctx)
{
    
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
resp_ctx::~resp_ctx()
{
        // -------------------------------------------------
        // delete body args
        // -------------------------------------------------
        for(arg_list_t::iterator i_q = m_body_arg_list.begin();
            i_q != m_body_arg_list.end();
            ++i_q)
        {
                if (i_q->m_key) { free(i_q->m_key); i_q->m_key = NULL; }
                if (i_q->m_val) { free(i_q->m_val); i_q->m_val = NULL; }
        }
        // -------------------------------------------------
        // delete body
        // -------------------------------------------------
        if (m_body_data)
        {
                free(m_body_data);
                m_body_data = NULL;
                m_body_len = 0;
        }
        // -------------------------------------------------
        // delete parser
        // -------------------------------------------------
        if (m_body_parser) { delete m_body_parser; m_body_parser = NULL;}
        // -------------------------------------------------
}

//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t resp_ctx::reset_phase_3()
{
        // -------------------------------------------------
        // clear headers
        // -------------------------------------------------
        m_header_list.clear();
        // -------------------------------------------------
        // clear tx map
        // -------------------------------------------------
        //m_cx_tx_map.clear();
        // -------------------------------------------------
        // clear header map
        // -------------------------------------------------
        m_header_map.clear();
        // -------------------------------------------------
        // clear vars
        // -------------------------------------------------
        m_init_phase_3 = false;
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t resp_ctx::init_phase_3()
{
        if (m_init_phase_3)
        {
                return WAFLZ_STATUS_OK;
        }

        // -------------------------------------------------
        // host
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_resp_host_cb)
        {
                int32_t l_s;
                // get src address
                l_s = m_callbacks->m_get_resp_host_cb(&m_host.m_data,
                                         &m_host.m_len,
                                         m_ctx);
                if (l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }

        // -------------------------------------------------
        // get uri, url and quert string
        // According to modsecurity:
        //
        // (REQUEST_URI) : holds the full request URL
        // including the query string data
        // (e.g., /index.php?p=X). However, it will never
        // contain a domain name, even if it was provided on
        // the request line.
        //
        // (REQUEST_URI_RAW): will contain the domain
        // name if it was provided on the request line
        // (e.g., http://www.example.com/index.php?p=X
        // The domain name depends on request line.
        // The most common form is origin-form according to
        // https://tools.ietf.org/html/rfc7230#section-5.3.1
        // waflz only supports origin form at this time,
        // meaning uri=uri
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_resp_uri_cb)
        {
                int32_t l_s;
                // get uri
                l_s = m_callbacks->m_get_resp_uri_cb(&m_uri.m_data,
                                                     &m_uri.m_len,
                                                     m_ctx);
                if (l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // get path length w/o q string
                // -----------------------------------------
                m_uri_path_len = m_uri.m_len;
                const char *l_q = NULL;
                l_q = (const char *)memchr(m_uri.m_data, '?', m_uri.m_len);
                if (l_q)
                {
                        m_uri_path_len = l_q - m_uri.m_data;
                }
        }

        // -------------------------------------------------
        // headers
        // -------------------------------------------------
        uint32_t l_hdr_size = 0;
        if (m_callbacks && m_callbacks->m_get_resp_header_size_cb)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_resp_header_size_cb(&l_hdr_size, m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_resp_header_size_cb");
                }
        }
        for(uint32_t i_h = 0; i_h < l_hdr_size; ++i_h)
        {
                const_arg_t l_hdr;
                if (!m_callbacks || !m_callbacks->m_get_resp_header_w_idx_cb)
                {
                        continue;
                }
                int32_t l_s;
                l_s = m_callbacks->m_get_resp_header_w_idx_cb(&l_hdr.m_key, &l_hdr.m_key_len,
                                                 &l_hdr.m_val, &l_hdr.m_val_len,
                                                 m_ctx,
                                                 i_h);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_resp_header_w_idx_cb: idx: %u", i_h);
                        continue;
                }
                if (!l_hdr.m_key)
                {
                        continue;
                }
                // -----------------------------------------
                // else just add header...
                // -----------------------------------------
                else
                {
                        m_header_list.push_back(l_hdr);
                        // ---------------------------------
                        // map
                        // ---------------------------------
                        data_t l_key;
                        l_key.m_data = l_hdr.m_key;
                        l_key.m_len = l_hdr.m_key_len;
                        data_t l_val;
                        l_val.m_data = l_hdr.m_val;
                        l_val.m_len = l_hdr.m_val_len;
                        m_header_map[l_key] = l_val;
                }
                // -----------------------------------------
                // parse content-type header...
                // e.g: Content-type:multipart/form-data; application/xml(asdhbc)  ;   aasdhhhasd;asdajj-asdad    ;; ;;"
                // -----------------------------------------
                if (strncasecmp(l_hdr.m_key, "Content-Type", sizeof("Content-Type") - 1) == 0)
                {
                        parse_content_type(m_content_type_list, &l_hdr);
                }
                // Get content-length, to be verified in phase 2
                if (strncasecmp(l_hdr.m_key, "Content-Length", sizeof("Content-Length") - 1) == 0)
                {
                        m_content_length = strntoul(l_hdr.m_val , l_hdr.m_val_len, NULL, 10);
                }
        }
        m_init_phase_3 = true;
        return WAFLZ_STATUS_OK;
}

int32_t resp_ctx::init_phase_4(const ctype_parser_map_t &a_ctype_parser_map)
{
        if (m_init_phase_4)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // request body data
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get content length
        // -------------------------------------------------
        if (m_content_length == ULONG_MAX)
        {
                // TODO -return reason...
                m_init_phase_4 = true;
                return WAFLZ_STATUS_OK;
        }
        if (m_content_length <= 0)
        {
                m_init_phase_4 = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // calculate body size
        // -------------------------------------------------
        uint32_t l_body_len;
        l_body_len = m_content_length > m_body_len_max ? m_body_len_max : m_content_length;
        //NDBG_PRINT("body len %d\n", l_body_len);
        // -------------------------------------------------
        // TODO -413 on > max???
        // -------------------------------------------------
        // TODO -should respond here and 413 the request???
        // -------------------------------------------------
        // get content type
        // -------------------------------------------------
        if (!m_content_type_list.size())
        {
                m_init_phase_4 = true;
                return WAFLZ_STATUS_OK;
        }
        if (!m_content_type_list.size())
        {
                m_init_phase_4 = true;
                return WAFLZ_STATUS_OK;
        }
        // Get the first one from list
        // TODO: may be check through the list?
        data_t l_type = m_content_type_list.front();
        std::string l_ct;
        l_ct.assign(l_type.m_data, l_type.m_len);
        ctype_parser_map_t::const_iterator i_p = a_ctype_parser_map.find(l_ct);
        if (i_p == a_ctype_parser_map.end())
        {
                m_init_phase_4 = true;
                return WAFLZ_STATUS_OK;
        }
        if (m_body_parser)
        {
                delete m_body_parser;
                m_body_parser = NULL;
        }
        // -------------------------------------------------
        // init parser...
        // -------------------------------------------------
        switch(i_p->second)
        {
                // -------------------------------------------------
                // PARSER_NONE
                // -------------------------------------------------
                case PARSER_NONE:
                {
                        // do nothing...
                        m_init_phase_4 = true;
                        return WAFLZ_STATUS_OK;
                }
                // -------------------------------------------------
                // default
                // -------------------------------------------------
                default:
                {
                        // do nothing...
                        m_init_phase_4 = true;
                        return WAFLZ_STATUS_OK;
                }
        }
        if (!m_body_parser)
        {
                // do nothing...
                m_init_phase_4 = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // init parser
        // -------------------------------------------------
        l_s = m_body_parser->init();
        if (l_s != WAFLZ_STATUS_OK)
        {
                // do nothing...
                //NDBG_PRINT("error m_body_parser->init()\n");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // TODO get response body
        // -------------------------------------------------
        if (!m_callbacks->m_get_resp_body_str_cb)
        {
                m_init_phase_4 = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // allocate max body size
        // -------------------------------------------------
        if (m_body_data)
        {
                free(m_body_data);
                m_body_data = NULL;
                m_body_len = 0;
        }
        m_body_data = (char *)malloc(sizeof(char)*l_body_len);
        bool l_is_eos = false;
        uint32_t l_rd_count = 0;
        uint32_t l_rd_count_total = 0;
        // -------------------------------------------------
        // while body data...
        // -------------------------------------------------
        while(!l_is_eos &&
              (l_rd_count_total < l_body_len))
        {
                l_rd_count = 0;
                char *l_buf = m_body_data+l_rd_count_total;
                uint32_t l_to_read = l_body_len-l_rd_count_total;
                l_s = m_callbacks->m_get_resp_body_str_cb(l_buf,
                                             &l_rd_count,
                                             &l_is_eos,
                                             m_ctx,
                                             l_to_read);
                if (l_s != 0)
                {
                        m_init_phase_4 = true;
                        return WAFLZ_STATUS_OK;
                }
                if (!l_rd_count)
                {
                        continue;
                }
                // -----------------------------------------
                // process chunk
                // -----------------------------------------
                l_s = m_body_parser->process_chunk(l_buf, l_rd_count);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        //NDBG_PRINT("error m_body_parser->process_chunk()\n");
                        // Set request body error var in tx map and return
                        //m_cx_tx_map["REQBODY_ERROR"] = "1";
                        m_init_phase_4 = true;
                        return WAFLZ_STATUS_OK;
                }
                l_rd_count_total += l_rd_count;
                //NDBG_PRINT("read: %6d / %6d\n", (int)l_rd_count, l_rd_count_total);
        }
        m_body_len = l_rd_count_total;
        // -------------------------------------------------
        // finish
        // -------------------------------------------------
        l_s = m_body_parser->finish();
        if (l_s != WAFLZ_STATUS_OK)
        {
                // Set request body error var in tx map and return
                // m_cx_tx_map["REQBODY_ERROR"] = "1";
                m_init_phase_4 = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // cap the arg list size
        // -------------------------------------------------
        for(arg_list_t::iterator i_k = m_body_arg_list.begin();
            i_k != m_body_arg_list.end();
            ++i_k)
        {
                if (i_k->m_key_len > s_body_arg_len_cap)
                {
                        i_k->m_key_len = s_body_arg_len_cap;
                }
                if (i_k->m_val_len > s_body_arg_len_cap)
                {
                        i_k->m_val_len = s_body_arg_len_cap;
                }
        }
        m_init_phase_4 = true;
        return WAFLZ_STATUS_OK;
}

}
