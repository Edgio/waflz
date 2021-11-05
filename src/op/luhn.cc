//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
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
#include "op/luhn.h"
#include <ctype.h>
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details Luhn Mod-10 Method (ISO 2894/ANSI 4.13)
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
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
