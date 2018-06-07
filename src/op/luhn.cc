//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    luhn.cc
//: \details: TODO
//: \author:  Reed P. Morrison
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
#include "op/luhn.h"
#include <ctype.h>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: \details Luhn Mod-10 Method (ISO 2894/ANSI 4.13)
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
bool luhn_validate(const char *a_buf, uint32_t a_buf_len)
{
        uint32_t l_sum[2] = { 0, 0 };
        bool l_odd = false;
        uint32_t l_digits = 0;
        // -------------------------------------------------
        // weight lookup table
        // -------------------------------------------------
        // Weighted lookup table:
        // precalculated (i_c = index):
        //   i_c*2 + (( (i_c*2) > 9 ) ? -9 : 0)
        // -------------------------------------------------
        static const int s_w_table[10] = {
                        0, 2, 4, 6, 8, 1, 3, 5, 7, 9
        };
        // -------------------------------------------------
        // add up l_digits (weighted l_digits via lookup
        // table) for both l_odd and even CC numbers to
        // avoid 2 passes.
        // -------------------------------------------------
        for(uint32_t i_c = 0; i_c < a_buf_len; ++i_c)
        {
                if(!isdigit(a_buf[i_c]))
                {
                        continue;
                }
                // -----------------------------------------
                // add to sum...
                // -----------------------------------------
                if(l_odd)
                {
                        l_sum[0] += (a_buf[i_c] - '0');
                        l_sum[1] += s_w_table[a_buf[i_c] - '0'];
                }
                else
                {
                        l_sum[0] += s_w_table[a_buf[i_c] - '0'];
                        l_sum[1] += (a_buf[i_c] - '0');
                }
                // -----------------------------------------
                // alternate weights
                // -----------------------------------------
                l_odd = true - l_odd;
                ++l_digits;
        }
        // -------------------------------------------------
        // no digits...
        // -------------------------------------------------
        if(l_digits == 0)
        {
                return false;
        }
        // -------------------------------------------------
        // mod 10 on sum
        // -------------------------------------------------
        l_sum[l_odd] %= 10;
        // -------------------------------------------------
        // if the result is a zero the card is valid.
        // -------------------------------------------------
        return l_sum[l_odd] ? false : true;
}
}
