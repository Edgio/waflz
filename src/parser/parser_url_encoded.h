//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef __PARSER_URL_ENCODED_H
#define __PARSER_URL_ENCODED_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <waflz/parser.h>
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! parser_url_encoded
//! ----------------------------------------------------------------------------
class parser_url_encoded: public parser
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        parser_url_encoded(rqst_ctx *a_rqst_ctx);
        ~parser_url_encoded();
        int32_t init(void);
        int32_t process_chunk(const char *a_buf, uint32_t a_len);
        int32_t finish(void);
        parser_t get_type(void) { return PARSER_URL_ENCODED; }
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        parser_url_encoded(const parser_url_encoded &);
        parser_url_encoded& operator=(const parser_url_encoded &);
};
}
#endif
