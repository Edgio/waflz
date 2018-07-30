//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    decode.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    12/07/2014
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
#ifndef _PARSE_H
#define _PARSE_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/arg.h"
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: prototypes
//: ----------------------------------------------------------------------------
int32_t css_decode(char **ao_buf, uint32_t &ao_len, const char *a_buf, uint32_t a_len);
int32_t html_entity_decode(char **ao_buf, uint32_t &ao_len, const char *a_buf, uint32_t a_len);
int32_t js_decode_ns(char **ao_buf, uint32_t &ao_len, const char *a_buf, uint32_t a_len);
int32_t normalize_path(char **ao_buf, uint32_t &ao_len, const char *a_buf, uint32_t a_len, bool a_is_windows);
int32_t parse_args(arg_list_t &ao_arg_list, uint32_t &ao_invalid_cnt, const char *a_buf, uint32_t a_len, char a_arg_sep);
int32_t parse_cookies(const_arg_list_t &ao_cookie_list, const char *a_buf, uint32_t a_len);
int32_t urldecode_ns(char **ao_buf, uint32_t &ao_len, uint32_t &ao_invalid_count, const char *a_buf, uint32_t a_len);
int32_t urldecode_uni_ns(char **ao_buf, uint32_t &ao_len, const char *a_buf, uint32_t a_len);
int32_t utf8_to_unicode(char **ao_buf, uint32_t &ao_len, const char *a_buf, uint32_t a_len);
int32_t validate_utf8(bool &ao_valid, const char **ao_err_msg, uint32_t &ao_err_off, const char *a_buf, uint32_t a_len);
int32_t parse_content_type(data_list_t &ao_data_list, const_arg_t *a_hdr);
}
#endif //#ifndef _PARSE_H
