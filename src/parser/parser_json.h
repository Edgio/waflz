//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef __PARSER_JSON_H
#define __PARSER_JSON_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/parser.h"
#include "yajl/yajl_parse.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define PARSER_JSON_PREFIX_LEN_MAX 256
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
typedef struct json_data json_data;
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! parser_json
//! ----------------------------------------------------------------------------
class parser_json: public parser
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        parser_json(rqst_ctx *a_rqst_ctx);
        ~parser_json();
        int32_t init(void);
        int32_t process_chunk(const char *a_buf, uint32_t a_len);
        int32_t finish(void);
        parser_t get_type(void) { return PARSER_JSON; }
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        yajl_handle m_handle;
        yajl_status m_status;
        unsigned char *m_error;
        unsigned char m_prefix[PARSER_JSON_PREFIX_LEN_MAX];
        unsigned char m_current_key[PARSER_JSON_PREFIX_LEN_MAX];
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        parser_json(const parser_json &);
        parser_json& operator=(const parser_json &);
};
}
#endif
