//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    string_util.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    03/09/2017
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
#ifndef _STRING_UTIL_H_
#define _STRING_UTIL_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include <sstream>
#include <string>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: utils
//: ----------------------------------------------------------------------------
// file/path manipulation
std::string get_file_wo_path(const std::string &a_filename);
std::string get_file_path(const std::string &a_filename);
std::string get_base_filename(const std::string &a_filename);
std::string get_file_ext(const std::string &a_filename);
std::string get_file_wo_ext(const std::string &a_filename);
// hex to int
int32_t convert_hex_to_uint(uint64_t &ao_val, const char *a_str);
char * strnstr(const char *s, const char *find, size_t slen);
long int strntol(const char *a_str, size_t a_size, char **ao_end, int a_base);
int64_t strntoll(const char *a_str, size_t a_size, char **ao_end, int a_base);
unsigned long int strntoul(const char *a_str, size_t a_size, char **ao_end, int a_base);
uint64_t strntoull(const char *a_str, size_t a_size, char **ao_end, int a_base);
size_t strlcat(char *a_dst, const char *a_src, size_t a_dsize);
int32_t convert_to_lower_case(char** ao_out, size_t& ao_len, const char* a_src, size_t a_len);
#if defined(__APPLE__) || defined(__darwin__)
void * memrchr(const void *s, int c, size_t n);
#endif
template <typename T>
std::string to_string(const T& a_num)
{
		std::stringstream l_s;
        l_s << a_num;
        return l_s.str();
}
int32_t colorize_string(std::string &ao_string);
}
#endif
