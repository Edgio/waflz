//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "event.pb.h"
#include "waflz/def.h"
#include "waflz/resp_ctx.h"
#include "waflz/geoip2_mmdb.h"
#include "waflz/string_util.h"
#include "core/decode.h"
#include "op/regex.h"
#include "support/ndebug.h"
#include "support/time_util.h"
#include "parser/parser_url_encoded.h"
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
uint32_t rqst_ctx::s_body_arg_len_cap = _DEFAULT_BODY_ARG_LEN_CAP;

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
        m_body_len_max(a_body_len_max),
        m_body_data(NULL),
        m_body_len(0),
        m_body_parser(),

        // -------------------------------------------------
        // *************************************************
        // xml optimization
        // *************************************************
        // -------------------------------------------------
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

}
}