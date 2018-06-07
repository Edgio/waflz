//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    arg.h
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
#ifndef _ARG_H
#define _ARG_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <string>
#include <list>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef struct arg {
        char *m_key;
        uint32_t m_key_len;
        char *m_val;
        uint32_t m_val_len;
        void clear(void)
        {
                m_key = NULL;
                m_key_len = 0;
                m_val = NULL;
                m_val_len = 0;
        }
} arg_t;
typedef std::list <arg_t> arg_list_t;
typedef struct const_arg {
        const char *m_key;
        uint32_t m_key_len;
        const char *m_val;
        uint32_t m_val_len;
        void clear(void)
        {
                m_key = NULL;
                m_key_len = 0;
                m_val = NULL;
                m_val_len = 0;
        }
} const_arg_t;
typedef std::list <const_arg_t> const_arg_list_t;
}
#endif //#ifndef _ARG_H
