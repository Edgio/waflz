//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "regex.h"
#define PCRE2_CODE_UNIT_WIDTH 8
#include "pcre2.h"
#include "support/ndebug.h"
#include <string.h>
#include <string>
#include <list>
#include "waflz/trace.h"
#include "support/time_util.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _WAFLZ_PCRE_MATCH_LIMIT 1000
#define _WAFLZ_PCRE_MATCH_LIMIT_RECURSION 1000
#define _WAFLZ_PCRE_GLOBAL_BUFFER_SIZE 256
namespace ns_waflz
{
PCRE2_UCHAR g_buffer[_WAFLZ_PCRE_GLOBAL_BUFFER_SIZE];
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
regex::regex(void):
        m_regex(nullptr),
        m_ctx(nullptr),
        m_err_ptr(0),
        m_err_off(-1)
{}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
regex::~regex()
{
        if(m_regex != nullptr)
        {
                pcre2_code_free(m_regex);
                m_regex = nullptr;
        }
        if (m_ctx != nullptr)
        {
                pcre2_match_context_free(m_ctx);
                m_ctx = nullptr;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void regex::get_err_info(const char** a_reason, int& a_offset)
{
        *a_reason = (char*) g_buffer;
        a_offset = m_err_off;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t regex::init(const char* a_buf, uint32_t a_len)
{
        if(!a_buf ||
           (a_len == 0) ||
           (strnlen(a_buf, a_len) == 0))
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_regex_str.assign(a_buf, a_len);
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        m_regex = pcre2_compile((PCRE2_SPTR) m_regex_str.c_str(),
                                m_regex_str.length(),
                                PCRE2_DUPNAMES|PCRE2_DOTALL|PCRE2_MULTILINE,
                                &m_err_ptr,
                                &m_err_off,
                                nullptr);
        if(m_regex == nullptr)
        {
                pcre2_get_error_message(m_err_ptr, g_buffer, sizeof(g_buffer));
                return WAFLZ_STATUS_ERROR;
        }
        int l_rc;
        l_rc = pcre2_jit_compile(m_regex, PCRE2_JIT_COMPLETE);
        if (l_rc != 0)
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_ctx = pcre2_match_context_create(nullptr);
        if (m_ctx == nullptr)
        {
                return WAFLZ_STATUS_ERROR;
        }
        pcre2_set_match_limit(m_ctx, _WAFLZ_PCRE_MATCH_LIMIT);
        pcre2_set_recursion_limit(m_ctx, _WAFLZ_PCRE_MATCH_LIMIT_RECURSION);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int regex::compare(const char* a_buf, uint32_t a_len, std::string* ao_captured)
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
        // match first only
        // -----------------------------------------
        int l_s;
        pcre2_match_data* l_match_data = nullptr;
        if (m_regex != nullptr) {
                l_match_data = pcre2_match_data_create_from_pattern(m_regex, nullptr);
                if (l_match_data == nullptr)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        l_s = pcre2_match(m_regex,
                          (PCRE2_SPTR) a_buf,
                          a_len,
                          0,
                          0,
                          l_match_data,
                          m_ctx);
        if(l_s == PCRE2_ERROR_MATCHLIMIT || l_s == PCRE2_ERROR_RECURSIONLIMIT)
        {
                pcre2_match_data_free(l_match_data); // Release memory used for the match
                return WAFLZ_STATUS_ERROR;
        }
        PCRE2_SIZE* l_ovector = pcre2_get_ovector_pointer(l_match_data);
        // -----------------------------------------
        // optional save first capture...
        // -----------------------------------------
        if(ao_captured &&
           (l_s > 0))
        {
                ao_captured->assign(a_buf + l_ovector[0],
                                    (l_ovector[1] - l_ovector[0]));
        }
        pcre2_match_data_free(l_match_data); // Release memory used for the match
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int regex::compare_all(const char* a_buf, uint32_t a_len, data_list_t* ao_captured)
{
        // -----------------------------------------
        // No check for empty input
        // Input can be empty. e.g empty headers
        // -----------------------------------------
        int l_s;
        int l_offset = 0;
        int l_ret_val = 0;
        pcre2_match_data* l_match_data = nullptr;
        if (m_regex != nullptr) {
                l_match_data = pcre2_match_data_create_from_pattern(m_regex, nullptr);
                if (l_match_data == nullptr)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -----------------------------------------
        // Get all matches
        // -----------------------------------------
        do
        {
                l_s = pcre2_match(m_regex,
                                  (PCRE2_SPTR) a_buf,
                                  a_len,
                                  l_offset,
                                  0,
                                  l_match_data,
                                  m_ctx);
                if(l_s == PCRE2_ERROR_MATCHLIMIT || l_s ==  PCRE2_ERROR_RECURSIONLIMIT)
                {
                        pcre2_match_data_free(l_match_data); // Release memory used for the match
                        return WAFLZ_STATUS_ERROR;
                }
                // ---------------------------------
                // loop over matches
                // ---------------------------------
                PCRE2_SIZE* l_ovector = pcre2_get_ovector_pointer(l_match_data);
                for(int i_t = 0; i_t < l_s; ++i_t)
                {
                        l_ret_val++;
                        data_t l_data;
                        uint32_t l_start = l_ovector[2*i_t];
                        uint32_t l_end = l_ovector[2*i_t+1];
                        uint32_t l_len = l_end - l_start;
                        if(l_end > a_len)
                        {
                            l_s = 0;
                            break;
                        }
                        if(l_len == 0)
                        {
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
        } while (l_s > 0);
        pcre2_match_data_free(l_match_data); // Release memory used for the match
        return l_ret_val;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void regex::display(void)
{
        // -------------------------------------------------
        // info
        // -------------------------------------------------
        int l_s;
        UNUSED(l_s);
#define _DISPLAY_PCRE_PROP_U(_what) do { \
                uint32_t l_opt; \
                l_s = pcre2_pattern_info(m_regex, _what, &l_opt); \
                NDBG_OUTPUT(":%s: %u\n", #_what, l_opt); \
        } while(0)
#define _DISPLAY_PCRE_PROP_UL(_what) do { \
                size_t l_opt; \
                l_s = pcre2_pattern_info(m_regex, _what, &l_opt); \
                NDBG_OUTPUT(":%s: %lu\n", #_what, l_opt); \
        } while(0)
        _DISPLAY_PCRE_PROP_U(PCRE2_INFO_BACKREFMAX);
        _DISPLAY_PCRE_PROP_U(PCRE2_INFO_CAPTURECOUNT);
        _DISPLAY_PCRE_PROP_UL(PCRE2_INFO_JITSIZE);
        _DISPLAY_PCRE_PROP_U(PCRE2_INFO_MINLENGTH);
        _DISPLAY_PCRE_PROP_U(PCRE2_INFO_MATCHLIMIT);
        _DISPLAY_PCRE_PROP_U(PCRE2_INFO_ARGOPTIONS);
        _DISPLAY_PCRE_PROP_U(PCRE2_INFO_SIZE);
        _DISPLAY_PCRE_PROP_UL(PCRE2_INFO_RECURSIONLIMIT);
}
}
