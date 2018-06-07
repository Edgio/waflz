//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    byte_range.h
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
#ifndef _BYTE_RANGE_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
#include <list>
namespace ns_waflz
{
//: ----------------------------------------------------------------------------
//: byte_range
//: ----------------------------------------------------------------------------
class byte_range
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        byte_range();
        ~byte_range();
        int32_t init(const char *a_buf, uint32_t a_len);
        bool is_within(const char *a_buf, uint32_t a_len);
        void show(void);
private:
        // -------------------------------------------------
        // private types
        // -------------------------------------------------
        typedef struct _range {
                int16_t m_from;
                int16_t m_to;
                _range(): m_from(-1), m_to(-1) {}
                void init(void) { m_from = -1; m_to = -1; }
        } range_t;
        typedef std::list<range_t> range_list_t;
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_initd;
        range_list_t m_range_list;
        char m_table[32];
};
//: ----------------------------------------------------------------------------
//: ****************************************************************************
//:                            U T I L I T I E S
//: ****************************************************************************
//: ----------------------------------------------------------------------------
int32_t create_byte_range(byte_range **ao_br, const std::string &a_str);
}
#endif
