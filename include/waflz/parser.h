//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    parser.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    04/06/2018
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
#ifndef __PARSER_H
#define __PARSER_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <strings.h>
#include <string>
#include <map>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
class rqst_ctx;
//: ----------------------------------------------------------------------------
//: parser types
//: ----------------------------------------------------------------------------
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
//: ----------------------------------------------------------------------------
//: parser abstract base class
//: ----------------------------------------------------------------------------
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
