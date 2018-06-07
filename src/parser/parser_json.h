//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    parser_json.h
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
#ifndef __PARSER_JSON_H
#define __PARSER_JSON_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/parser.h"
#include "yajl/yajl_parse.h"
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define PARSER_JSON_PREFIX_LEN_MAX 256
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
typedef struct json_data json_data;
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: parser_json
//: ----------------------------------------------------------------------------
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
