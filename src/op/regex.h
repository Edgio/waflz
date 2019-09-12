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
//: Includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "pcre.h"
#include "support/ndebug.h"
#include <string.h>
#include <string>
#include <list>
#include <re2/re2.h>
namespace ns_waflz
{
//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
class regex
{
public:
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        regex(void):
                m_regex(NULL),
                m_regex_study(NULL),
                m_regex_str(),
                m_re(NULL),
                m_err_ptr(NULL),
                m_err_off(-1)
        {}
        ~regex()
        {
                if(m_regex)
                {
                        pcre_free(m_regex);
                        m_regex = NULL;
                }
                if(m_regex_study)
                {
#ifdef PCRE_STUDY_JIT_COMPILE
                        pcre_free_study(m_regex_study);
#else
                        pcre_free(m_regex_study);
#endif
                        m_regex_study = NULL;
                }
                if(m_re)
                {
                        delete m_re;
                        m_re = NULL;
                }
        }
        void get_err_info(const char **a_reason, int &a_offset)
        {
                *a_reason = m_err_ptr;
                a_offset = m_err_off;
        }
        int32_t init(const char *a_buf, uint32_t a_len)
        {
                if(!a_buf ||
                   (a_len == 0) ||
                   (strnlen(a_buf, a_len) == 0))
                {
                        return WAFLZ_STATUS_ERROR;
                }
                const char *l_err_ptr;
                int l_err_off;
                m_regex_str.assign(a_buf, a_len);
                m_regex = pcre_compile(m_regex_str.c_str(),
                                       PCRE_DUPNAMES|PCRE_DOTALL|PCRE_MULTILINE,
                                       &l_err_ptr,
                                       &l_err_off,
                                       NULL);
                if(!m_regex)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                m_regex_study = pcre_study(m_regex,
                                           s_pcre_study_options,
                                           &m_err_ptr);
                m_regex_study->flags = PCRE_EXTRA_MATCH_LIMIT | PCRE_EXTRA_MATCH_LIMIT_RECURSION;
                m_regex_study->match_limit = 100;
                m_regex_study->match_limit_recursion = 100;

                // -----------------------------------------
                // if regex_study NULL not compiled with JIT
                // check m_err_ptr for error
                // -----------------------------------------
                if(m_err_ptr)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                printf("pcre-flags %lu\n", m_regex_study->flags);
                printf("pcre-matchlimit %lu\n",m_regex_study->match_limit);
                printf("pcre-matchlimitrecursion %lu\n", m_regex_study->match_limit_recursion);
                // -----------------------------------------
                // re2
                // -----------------------------------------
                m_re = new RE2(m_regex_str, RE2::Quiet);
                if(!m_re->ok())
                {
                        //NDBG_PRINT("%serror%s compiling: %s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, m_regex_str.c_str());
                }
                else
                {
                        //NDBG_PRINT("%sok%s    compiling: %s\n", ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF, m_regex_str.c_str());
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // TODO:
        // create function similar to compare_and_capture
        // -------------------------------------------------
        int compare(const char *a_buf, uint32_t a_len, std::string *ao_captured = NULL)
        {
                printf("Regex compare-input buffer- %s\n", a_buf);
                // -----------------------------------------
                // Check for NULL
                // -----------------------------------------
                if(!a_buf ||
                   (a_len == 0) ||
                   (strnlen(a_buf, a_len) == 0))
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // DA TODO:
                // Fix this. No point doing this
                // -----------------------------------------
                int l_ovecsize = 3;
                int l_ovector[3] = {0};
                int l_s;
                l_s = pcre_exec(m_regex,
                                m_regex_study,
                                a_buf,
                                a_len,
                                0,
                                0,
                                l_ovector,
                                // -------------------------
                                // Num elements in output
                                // vector
                                // -------------------------
                                l_ovecsize);
                // -----------------------------------------
                // Match succeeded but ovector too small
                // -----------------------------------------
                if(l_s == 0)
                {
                        printf("pcre match succeeded\n");
                        // ---------------------------------
                        // Number of elements in output
                        // vector, multiple of
                        // ---------------------------------
                        l_s = l_ovecsize / 3;
                }
                // -----------------------------------------
                // optional save first capture...
                // -----------------------------------------
                if(ao_captured &&
                   (l_s > 0))
                {
                        ao_captured->assign(a_buf + l_ovector[0],
                                            (l_ovector[1] - l_ovector[0]));
                        printf("Regex compare- captured string %s\n", ao_captured->c_str());
                }
                int l_int_match;
                std::string l_string_match;
                int l_s_re;
                l_s_re = RE2::FullMatch(a_buf, *m_re, &l_string_match, (void*)NULL, &l_int_match);
                if(l_s_re > 0)
                {
                        printf("RE2 compare-Matched String\n");
                }
                return l_s;
        }
        /// --------------------------------------------------------------------
        /// @brief  get all the mactches in a string
        /// @param  a_buf: input string, a_len: Length of input, ao_captured: data list
        /// @return Number of matches
        /// --------------------------------------------------------------------
        int compare_all(const char *a_buf, uint32_t a_len, data_list_t *ao_captured)
        {
                //printf("regex compare all - input buf - %s\n", a_buf);
                // -----------------------------------------
                // No check for empty input
                // Input can be empty. e.g empty headers
                // -----------------------------------------
                int l_ovecsize = 30;
                int l_ovector[30] = {0};
                int l_s;
                int l_offset = 0;
                int l_ret_val = 0;
                // Get all matches
                do
                {
                        l_s = pcre_exec(m_regex,
                                m_regex_study,
                                a_buf,
                                a_len,
                                l_offset,
                                0,
                                l_ovector,
                                // -------------------------
                                // Num elements in output
                                // vector
                                // -------------------------
                                l_ovecsize);
                        for (int i_t = 0; i_t < l_s; ++i_t)
                        {
                                l_ret_val++;
                                data_t l_data;
                                uint32_t l_start = l_ovector[2*i_t];
                                uint32_t l_end = l_ovector[2*i_t+1];
                                uint32_t l_len = l_end - l_start;
                                if (l_end > a_len) {
                                    l_s = 0;
                                    break;
                                }
                                if (l_len == 0) {
                                    l_s = 0;
                                    break;
                                }
                                l_offset = l_start + l_len;
                                if(ao_captured)
                                {
                                        l_data.m_data = a_buf + l_start;
                                        l_data.m_len = l_len;
                                        ao_captured->push_back(l_data);
                                        printf("Regex compare all- matched str %s\n", l_data.m_data);
                                }
                        }
                }while (l_s > 0);
                //int l_int_match;
                std::string l_string_match;
                int l_s_re;
                std::string input(a_buf, a_len);
                l_s_re = RE2::PartialMatch(input, *m_re, &l_string_match);
                printf("Regex compare val %d\n", l_s_re);
                if(l_s_re > 0)
                {
                        printf("RE2- compare all-Matched String- %s\n", l_string_match.c_str());
                }
                return l_ret_val;
        }
        const std::string &get_regex_string(void)
        {
                return m_regex_str;
        }
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // TODO FIX!!!
        //DISALLOW_DEFAULT_CTOR(regex);
        // Disallow copy/assign
        regex(const regex &);
        regex& operator=(const regex &);
        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        pcre* m_regex;
        pcre_extra* m_regex_study;
        std::string m_regex_str;
        RE2* m_re;
        // err info
        const char *m_err_ptr;
        int m_err_off;
        // -------------------------------------------------
        // Private static
        // -------------------------------------------------
#ifdef PCRE_STUDY_JIT_COMPILE
        static const int s_pcre_study_options = PCRE_STUDY_JIT_COMPILE;
#else
        static const int s_pcre_study_options = 0;
#endif
};
}
#endif
