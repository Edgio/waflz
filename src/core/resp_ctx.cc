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
//uint32_t rqst_ctx::s_body_arg_len_cap = _DEFAULT_BODY_ARG_LEN_CAP;

//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
resp_ctx::resp_ctx(void *a_ctx,
                   uint32_t a_body_len_max,
                   const resp_ctx_callbacks *a_callbacks,
                   bool a_parse_xml,
                   bool a_parse_json):
        m_an(),
        m_content_length(0),
        m_content_type_list(),
        m_header_map(),
        m_body_len_max(a_body_len_max),
        m_body_data(NULL),
        m_body_len(0),
        m_resp_status(0),
        m_body_parser(),
        m_body_arg_list(),
        // -------------------------------------------------
        // collections
        // -------------------------------------------------
        //m_cx_tx_map(),
        // -------------------------------------------------
        // state
        // -------------------------------------------------
        m_init_phase_3(false),
        m_init_phase_4(false),
        
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
int32_t resp_ctx::init_phase_3()
{
        if (m_init_phase_3)
        {
                return WAFLZ_STATUS_OK;
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
