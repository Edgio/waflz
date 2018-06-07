//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    md5_hasher.h
//: \details: TODO
//: \author:  David Andrews
//: \date:    02/07/2014
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
#ifndef _MD5_HASHER_H_
#define _MD5_HASHER_H_
//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include <openssl/md5.h>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: md5 hasher obj
//: ----------------------------------------------------------------------------
class md5_hasher
{
public:
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        //: ------------------------------------------------
        //: \details TODO
        //: \return  TODO
        //: ------------------------------------------------
        md5_hasher():m_ctx(),
                     m_finished(false),
                     m_hash_str()
        {
                MD5_Init(&m_ctx);
        }
        //: ------------------------------------------------
        //: \details TODO
        //: \return  TODO
        //: ------------------------------------------------
        void update(const char* str, unsigned int len)
        {
                MD5_Update(&m_ctx, (const unsigned char*) str, len);
        }
        //: ------------------------------------------------
        //: \details TODO
        //: \return  TODO
        //: ------------------------------------------------
        void finish()
        {
                if (!m_finished)
                {
                        unsigned char h[16];
                        MD5_Final(h, &m_ctx);
                        static const char hexchars[] =
                        {
                                '0', '1', '2', '3',
                                '4', '5', '6', '7',
                                '8', '9', 'a', 'b',
                                'c', 'd', 'e', 'f'
                        };
                        for (size_t i = 0; i < 16; ++i)
                        {
                                m_hash_str[2 * i + 0] = hexchars[(h[i] & 0xf0) >> 4];
                                m_hash_str[2 * i + 1] = hexchars[h[i] & 0x0f];
                        }
                        m_hash_str[32] = '\0';
                        m_finished = true;
                }
        }
        //: ------------------------------------------------
        //: \details TODO
        //: \return  TODO
        //: ------------------------------------------------
        const char* hash_str()
        {
                this->finish();
                return m_hash_str;
        }
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        md5_hasher(const md5_hasher&);
        md5_hasher& operator=(const md5_hasher&);
        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        MD5_CTX m_ctx;
        bool m_finished;
        char m_hash_str[33];
};
}
#endif // _MD5_HASHER_H_
