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
#ifndef _REGEX_H_
#define _REGEX_H_
//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "pcre.h"
#include "support/ndebug.h"
#include <string.h>
#include <string>
#include <list>
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
                // -----------------------------------------
                // if regex_study NULL not compiled with JIT
                // check m_err_ptr for error
                // -----------------------------------------
                if(m_err_ptr)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // TODO:
        // create function similar to compare_and_capture
        // -------------------------------------------------
        int compare(const char *a_buf, uint32_t a_len, std::string *ao_captured = NULL)
        {
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
                                }
                        }
                }while (l_s > 0);
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
