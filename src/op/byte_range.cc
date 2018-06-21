//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    byte_range.cc
//: \details: TODO
//: \author:  Reed P Morrison
//: \date:    04/26/2018
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
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "byte_range.h"
#include <stdlib.h>
#include <string.h>
#include "support/ndebug.h"
#include "support/string_util.h"
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#ifndef WAFLZ_STATUS_OK
  #define WAFLZ_STATUS_OK 0
#endif
#ifndef WAFLZ_STATUS_ERROR
  #define WAFLZ_STATUS_ERROR -1
#endif
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define SCAN_OVER_SPACE(l_line, l_char, l_line_len) \
        do { \
                while(isspace(int(*l_line)) && \
                      (l_char < l_line_len)) \
                {\
                        ++l_char;\
                }\
        } while(0)
namespace ns_waflz
{
//: ----------------------------------------------------------------------------
//: ****************************************************************************
//:                          B Y T E   R A N G E
//: ****************************************************************************
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
byte_range::byte_range():
        m_initd(false),
        m_range_list()
{
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
byte_range::~byte_range()
{
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t byte_range::init(const char *a_buf, uint32_t a_len)
{
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // grab a copy for tokenizing
        // -------------------------------------------------
        char *l_buf = NULL;
        l_buf = strndup(a_buf, a_len);
        if(!l_buf)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // *************************************************
        //                   P A R S E
        // *************************************************
        // -------------------------------------------------
        //NDBG_PRINT("parse: '%.*s'\n", a_len, a_buf);
        char *i_c;
        i_c = strtok(l_buf,",");
        range_t l_r;
        while(i_c != NULL)
        {
                //NDBG_PRINT("part:  '%s'\n", i_c);
                l_r.init();
                // -----------------------------------------
                // parse range...
                // -----------------------------------------
                char *l_sep = strstr(i_c, "-");
                // -----------------------------------------
                // single value
                // -----------------------------------------
                if(!l_sep)
                {
                        int32_t l_val;
                        //NDBG_PRINT("convert: %.*s\n", (int)strlen(i_c), i_c);
                        while(isspace(int(*i_c)) && *i_c) { ++i_c; }
                        l_val = strntol(i_c, strlen(i_c), NULL, 10);
                        if((l_val < 0) ||
                           (l_val > 255))
                        {
                                m_range_list.clear();
                                if(l_buf) { free(l_buf); l_buf = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                        l_r.m_from = (int16_t)l_val;
                        l_r.m_to = -1;
                        m_range_list.push_back(l_r);
                }
                // -----------------------------------------
                // range???
                // -----------------------------------------
                else
                {
                        int32_t l_from;
                        int32_t l_to;
                        //NDBG_PRINT("convert: %.*s\n", (int)(l_sep - i_c), i_c);
                        while(isspace(int(*i_c)) && *i_c) { ++i_c; }
                        l_from = strntol(i_c, (l_sep - i_c), NULL, 10);
                        if((l_from < 0) ||
                           (l_from > 255))
                        {
                                m_range_list.clear();
                                if(l_buf) { free(l_buf); l_buf = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                        //NDBG_PRINT("convert: %.*s\n", (int)(strlen(l_sep+1)), l_sep+1);
                        ++l_sep;
                        while(isspace(int(*l_sep)) && *l_sep) { ++l_sep; }
                        l_to = strntol(l_sep, strlen(l_sep), NULL, 10);
                        if((l_to < 0) ||
                           (l_to > 255))
                        {
                                m_range_list.clear();
                                if(l_buf) { free(l_buf); l_buf = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                        // check range
                        if(l_from >= l_to)
                        {
                                m_range_list.clear();
                                if(l_buf) { free(l_buf); l_buf = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                        l_r.m_from = (int16_t)l_from;
                        l_r.m_to = (int16_t)l_to;
                        m_range_list.push_back(l_r);
                }
                i_c = strtok(NULL, ",");
        }
        // TODO REMOVE
        //show();
        // -------------------------------------------------
        // *************************************************
        //                   T A B L E
        // *************************************************
        // -------------------------------------------------
        memset(m_table, 0, 32);
        for(range_list_t::const_iterator i_r = m_range_list.begin();
            i_r != m_range_list.end();
            ++i_r)
        {
                if(i_r->m_from == -1)
                {
                        continue;
                }
                // -----------------------------------------
                // single value
                // -----------------------------------------
                if(i_r->m_to == -1)
                {
                        uint16_t l_from = (uint16_t)i_r->m_from;
                        uint16_t l_idx = l_from >> 3;
                        uint16_t l_val = (1 << (l_from & 0x7));
                        m_table[l_idx] = (m_table[l_idx] | l_val);
                }
                // -----------------------------------------
                // range
                // -----------------------------------------
                else
                {
                        uint16_t l_from = (uint16_t)i_r->m_from;
                        uint16_t l_to = (uint16_t)i_r->m_to;
                        while(l_from <= l_to)
                        {
                                uint16_t l_idx = l_from >> 3;
                                uint16_t l_val = (1 << (l_from & 0x7));
                                m_table[l_idx] = (m_table[l_idx] | l_val);
                                ++l_from;
                        }
                }
        }
        if(l_buf) { free(l_buf); l_buf = NULL;}
        m_initd = true;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
bool byte_range::is_within(const char *a_buf, uint32_t a_len)
{
        if(!m_initd)
        {
                return WAFLZ_STATUS_ERROR;
        }
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // for each char...
        // -------------------------------------------------
        for(uint32_t i_c = 0; i_c < a_len; ++i_c)
        {
                uint8_t l_c = (uint8_t)(a_buf[i_c]);
                // -----------------------------------------
                // range check
                // -----------------------------------------
                if(!(m_table[l_c >> 3] & (1 << (l_c & 0x7))))
                {
                        return false;
                }
        }
        return true;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void byte_range::show(void)
{
        for(range_list_t::const_iterator i_r = m_range_list.begin();
            i_r != m_range_list.end();
            ++i_r)
        {
                NDBG_OUTPUT("FROM: %6d TO: %6d\n", i_r->m_from, i_r->m_to);
        }
}
//: ----------------------------------------------------------------------------
//: ****************************************************************************
//:                            U T I L I T I E S
//: ****************************************************************************
//: ----------------------------------------------------------------------------
int32_t create_byte_range(byte_range **ao_br, const std::string &a_str)
{
        if(!ao_br)
        {
                return WAFLZ_STATUS_ERROR;
        }
        if(*ao_br)
        {
                delete *ao_br;
                *ao_br = NULL;
        }
        byte_range *l_br = new byte_range();
        int32_t l_s;
        l_s = l_br->init(a_str.c_str(), a_str.length());
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_br) { delete l_br; l_br = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        *ao_br = l_br;
        return WAFLZ_STATUS_OK;
}
}
