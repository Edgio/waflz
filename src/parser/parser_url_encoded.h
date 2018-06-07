//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    parser_url_encoded.h
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
#ifndef __PARSER_URL_ENCODED_H
#define __PARSER_URL_ENCODED_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <waflz/parser.h>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: parser_url_encoded
//: ----------------------------------------------------------------------------
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
