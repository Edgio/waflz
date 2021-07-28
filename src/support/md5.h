//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _MD5_H_
#define _MD5_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <openssl/evp.h>
#include <stdint.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! md5 hasher obj
//! ----------------------------------------------------------------------------
class md5
{
public:
        // -------------------------------------------------
        // public constants
        // -------------------------------------------------
        static const uint16_t s_hash_len = 16;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        // -------------------------------------------------
        // constructor
        // -------------------------------------------------
        md5():
                m_ctx(),
                m_finished(false),
                m_hash_hex()
        {
                EVP_DigestInit_ex(&m_ctx, EVP_md5(), nullptr);
        }
        // -------------------------------------------------
        // update
        // -------------------------------------------------
        void update(const char* a_str, unsigned int a_len)
        {
                EVP_DigestUpdate(&m_ctx, (const unsigned char*)a_str, a_len);
        }
        // -------------------------------------------------
        // finish
        // -------------------------------------------------
        void finish()
        {
                if(m_finished)
                {
                        return;
                }
                EVP_DigestFinal_ex(&m_ctx, (unsigned char *)m_hash, nullptr);
                static const char s_hexchars[] =
                {
                        '0', '1', '2', '3',
                        '4', '5', '6', '7',
                        '8', '9', 'a', 'b',
                        'c', 'd', 'e', 'f'
                };
                for(size_t i = 0; i < s_hash_len; ++i)
                {
                        m_hash_hex[2 * i + 0] = s_hexchars[(m_hash[i] & 0xf0) >> 4];
                        m_hash_hex[2 * i + 1] = s_hexchars[m_hash[i] & 0x0f];
                }
                m_hash_hex[32] = '\0';
                m_finished = true;
        }
        // -------------------------------------------------
        // get_hash_hex
        // -------------------------------------------------
        const char* get_hash_hex()
        {
                finish();
                return m_hash_hex;
        }
        // -------------------------------------------------
        // get_hash
        // -------------------------------------------------
        const unsigned char* get_hash()
        {
                finish();
                return m_hash;
        }
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        md5(const md5&);
        md5& operator=(const md5&);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        EVP_MD_CTX m_ctx;
        bool m_finished;
        unsigned char m_hash[s_hash_len];
        char m_hash_hex[33];
};
}
#endif // _MD5_HASHER_H_
