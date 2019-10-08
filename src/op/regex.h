//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    regex.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    11/30/2016
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
#ifndef _REGEXX_H_
#define _REGEXX_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include <pcre.h>
#include <string>
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace ns_waflz
{
//: ----------------------------------------------------------------------------
//: regex
//: ----------------------------------------------------------------------------
class regex
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        regex(void);
        ~regex();
        void get_err_info(const char** a_reason, int& a_offset);
        int32_t init(const char* a_buf, uint32_t a_len);
        int compare(const char* a_buf, uint32_t a_len, std::string* ao_captured = NULL);
        int compare_all(const char* a_buf, uint32_t a_len, data_list_t* ao_captured);
        const std::string& get_regex_string(void) { return m_regex_str; }
        void display(void);
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // TODO FIX!!!
        //DISALLOW_DEFAULT_CTOR(regex);
        // Disallow copy/assign
        regex(const regex&);
        regex& operator=(const regex&);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        pcre* m_regex;
        pcre_extra* m_regex_study;
        std::string m_regex_str;
        // err info
        const char* m_err_ptr;
        int m_err_off;
        // -------------------------------------------------
        // private static
        // -------------------------------------------------
#ifdef PCRE_STUDY_JIT_COMPILE
        static const int s_pcre_study_options = PCRE_STUDY_JIT_COMPILE;
#else
        static const int s_pcre_study_options = 0;
#endif
};
}
#endif
