//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef __PARSER_H
#define __PARSER_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <strings.h>
#include <string>
#include <map>
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class rqst_ctx;
//! ----------------------------------------------------------------------------
//! parser types
//! ----------------------------------------------------------------------------
typedef enum _parser_t {
        PARSER_NONE = 0,
        PARSER_URL_ENCODED,
        PARSER_MULTIPART,
        PARSER_XML,
        PARSER_JSON
} parser_t;
struct px_header_case_i_comp
{
        bool operator() (const std::string& lhs, const std::string& rhs) const
        {
                return strcasecmp(lhs.c_str(), rhs.c_str()) < 0;
        }
};
typedef std::map <std::string, parser_t, px_header_case_i_comp> ctype_parser_map_t;
//! ----------------------------------------------------------------------------
//! parser abstract base class
//! ----------------------------------------------------------------------------
class parser
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        parser(rqst_ctx *a_rqst_ctx): m_rqst_ctx(a_rqst_ctx) {}
        virtual ~parser(void) {}
        virtual int32_t init(void) = 0;
        virtual int32_t process_chunk(const char *a_buf, uint32_t a_len) = 0;
        virtual int32_t finish(void) = 0;
        virtual parser_t get_type(void) = 0;
protected:
        // -------------------------------------------------
        // protected members
        // -------------------------------------------------
        rqst_ctx *m_rqst_ctx;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        parser(const parser &);
        parser& operator=(const parser &);
};
}
#endif
