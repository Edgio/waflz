//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    tx.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    09/30/2018
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
#include "waflz/def.h"
#include "rule.pb.h"
#include "core/tx.h"
#include "core/decode.h"
#include "support/ndebug.h"
#include <string.h>
// for sha1
#include <openssl/evp.h>
#include <vector>
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define TX(_type) \
        static int32_t _tx_cb_##_type(char **ao_buf, \
                                      uint32_t &ao_len, \
                                      const char *a_buf, \
                                      const uint32_t &a_len)
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: ****************************************************************************
//:                       T R A N S F O R M A T I O N S
//: ****************************************************************************
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(NONE)
{
        //NDBG_PRINT("...\n");
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(LENGTH)
{
        //NDBG_PRINT("...\n");
        ao_len = asprintf(ao_buf, "%u", a_len);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(COMPRESSWHITESPACE)
{
        //NDBG_PRINT("...\n");
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        // -------------------------------------------------
        // non-breaking space char
        // -------------------------------------------------
#define _NBSP 160
        // -------------------------------------------------
        // copy string
        // -------------------------------------------------
        char *l_buf = strndup(a_buf, a_len);
        // -------------------------------------------------
        // calc new length
        // -------------------------------------------------
        uint32_t l_buf_len = a_len;
        l_buf_len = strnlen(l_buf, a_len);
        if(!l_buf ||
           !l_buf_len)
        {
                if(l_buf) { free(l_buf); l_buf = NULL; }
                return WAFLZ_STATUS_OK;
        }
        uint32_t i_j = 0;
        uint32_t l_cnt = 0;
        uint32_t i_i = 0;
        // -------------------------------------------------
        // compress...
        // -------------------------------------------------
        while(i_i < l_buf_len)
        {
                if(isspace(l_buf[i_i]) ||
                   (l_buf[i_i] == _NBSP))
                {
                        ++l_cnt;
                }
                else
                {
                        if(l_cnt)
                        {
                                l_buf[i_j] = ' ';
                                l_cnt = 0;
                                ++i_j;
                        }
                        l_buf[i_j] = l_buf[i_i];
                        ++i_j;
                }
                ++i_i;
        }
        if(l_cnt)
        {
                l_buf[i_j] = ' ';
                ++i_j;
        }
        *ao_buf = l_buf;
        ao_len = i_j;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(REMOVEWHITESPACE)
{
        //NDBG_PRINT("...\n");
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        // -------------------------------------------------
        // copy string
        // -------------------------------------------------
        char *l_buf = (char *)malloc(sizeof(char)*a_len);
        uint32_t i_i = 0;
        uint32_t i_j = 0;
        // -------------------------------------------------
        // for each char...
        // -------------------------------------------------
        while(i_i < a_len)
        {
                // if non-space, copy over
                if(!isspace(a_buf[i_i]) &&
                   (a_buf[i_i] != _NBSP))
                {
                        l_buf[i_j] = a_buf[i_i];
                        ++i_j;
                }
                ++i_i;
        }
        *ao_buf = l_buf;
        ao_len = i_j;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(REMOVENULLS)
{
        //NDBG_PRINT("...\n");
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        // -------------------------------------------------
        // copy str
        // -------------------------------------------------
        char *l_buf = (char *)malloc(sizeof(char)*a_len + 1);
        memcpy(l_buf, a_buf, a_len);
        l_buf[a_len] = '\0';
        // -------------------------------------------------
        // replace any null chars with space
        // -------------------------------------------------
        uint32_t i_i = 0;
        while(i_i < a_len)
        {
            if(l_buf[i_i] == '\0')
            {
                l_buf[i_i] = ' ';
            }
            ++i_i;
        }
        *ao_buf = l_buf;
        ao_len = a_len;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(LOWERCASE)
{
        //NDBG_PRINT("...\n");
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        char *l_buf = (char *)malloc(sizeof(char)*a_len + 1);
        l_buf[a_len] = '\0';
        ao_len = a_len;
        for(uint32_t i_idx = 0; i_idx < ao_len; ++i_idx)
        {
                l_buf[i_idx] = tolower((int)a_buf[i_idx]);
        }
        *ao_buf = l_buf;
        ao_len = a_len;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(REPLACECOMMENTS)
{
        //NDBG_PRINT("...\n");
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        char *l_buf = NULL;
        l_buf = (char *)malloc(sizeof(char)*a_len);
        uint32_t i_c = 0;
        uint32_t i_j = 0;
        bool l_in_comment = false;
        // -------------------------------------------------
        // for each char...
        // -------------------------------------------------
        while(i_c < a_len)
        {
                // -----------------------------------------
                // not in comment
                // search for comment starter
                // -----------------------------------------
                if(!l_in_comment)
                {
                        // ---------------------------------
                        // c-style /*
                        // ---------------------------------
                        if((i_c + 1 < a_len) &&
                           (a_buf[i_c]     == '/') &&
                           (a_buf[i_c + 1] == '*'))
                        {
                                i_c += 2;
                                l_in_comment = true;
                        }
                        // ---------------------------------
                        // not in comment -copy over
                        // ---------------------------------
                        else
                        {
                                l_buf[i_j] = a_buf[i_c];
                                ++i_c;
                                ++i_j;
                        }
                }
                // -----------------------------------------
                // in comment
                // search for comment terminator
                // -----------------------------------------
                else
                {
                        // ---------------------------------
                        // c-style */
                        // ---------------------------------
                        if((i_c + 1 < a_len) &&
                           (a_buf[i_c]     == '*') &&
                           (a_buf[i_c + 1] == '/'))
                        {
                                i_c += 2;
                                l_buf[i_j] = ' ';
                                ++i_j;
                                l_in_comment = false;
                        }
                        else
                        {
                                ++i_c;
                        }
                }
        }
        // -------------------------------------------------
        // add space if in comment???
        // -------------------------------------------------
        if(l_in_comment)
        {
                l_buf[i_j++] = ' ';
        }
        *ao_buf = l_buf;
        ao_len = i_j;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(REMOVECOMMENTS)
{
        //NDBG_PRINT("...\n");
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        char *l_buf = NULL;
        l_buf = (char *)malloc(sizeof(char)*a_len);
        uint32_t i_c = 0;
        uint32_t i_j = 0;
        bool l_in_comment = false;
        // -------------------------------------------------
        // for each char...
        // -------------------------------------------------
        while(i_c < a_len)
        {
                // -----------------------------------------
                // not in comment
                // search for comment starter
                // -----------------------------------------
                if(!l_in_comment)
                {
                        // ---------------------------------
                        // c-style /*
                        // ---------------------------------
                        if((i_c + 1 < a_len) &&
                           (a_buf[i_c]     == '/') &&
                           (a_buf[i_c + 1] == '*'))
                        {
                                l_in_comment = true;
                                i_c += 2;
                        }
                        // ---------------------------------
                        // xml/html <!--
                        // ---------------------------------
                        else if((i_c + 3 < a_len) &&
                                (a_buf[i_c]     == '<') &&
                                (a_buf[i_c + 1] == '!') &&
                                (a_buf[i_c + 2] == '-') &&
                                (a_buf[i_c + 3] == '-'))
                        {
                                l_in_comment = true;
                                i_c += 4;
                        }
                        // ---------------------------------
                        // ???
                        // ---------------------------------
                        else if((i_c + 1 < a_len) &&
                                (a_buf[i_c]     == '-') &&
                                (a_buf[i_c + 1] == '-'))
                        {
                                l_buf[i_c] = ' ';
                                break;
                        }
                        // ---------------------------------
                        // shell style #
                        // ---------------------------------
                        else if(a_buf[i_c] == '#')
                        {
                                l_buf[i_c] = ' ';
                                break;
                        }
                        // ---------------------------------
                        // not in comment -copy char
                        // ---------------------------------
                        else
                        {
                                l_buf[i_j] = a_buf[i_c];
                                ++i_c;
                                ++i_j;
                        }
                }
                // -----------------------------------------
                // in comment
                // search for comment terminator
                // -----------------------------------------
                else
                {
                        // ---------------------------------
                        // c-style */
                        // ---------------------------------
                        if((i_c + 1 < a_len) &&
                           (a_buf[i_c]     == '*') &&
                           (a_buf[i_c + 1] == '/'))
                        {
                                i_c += 2;
                                l_buf[i_j] = a_buf[i_c];
                                ++i_c;
                                ++i_j;
                                l_in_comment = false;
                        }
                        // ---------------------------------
                        // xml/html -->
                        // ---------------------------------
                        else if((i_c + 2 < a_len) &&
                                (a_buf[i_c]     == '-') &&
                                (a_buf[i_c + 1] == '-') &&
                                (a_buf[i_c + 2] == '>'))
                        {
                                i_c += 3;
                                l_buf[i_j] = a_buf[i_c];
                                ++i_c;
                                ++i_j;
                                l_in_comment = false;
                        }
                        // ---------------------------------
                        // still in comment -skip fwd
                        // ---------------------------------
                        else
                        {
                                ++i_c;
                        }
                }
        }
        // -------------------------------------------------
        // add space if in comment???
        // -------------------------------------------------
        if(l_in_comment)
        {
                l_buf[i_j++] = ' ';
        }
        *ao_buf = l_buf;
        ao_len = i_j;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(CMDLINE)
{
        //NDBG_PRINT("...\n");
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        bool l_is_space = false;
        char *l_buf = NULL;
        l_buf = (char *)malloc(sizeof(char)*a_len);
        uint32_t i_c = 0;
        uint32_t i_j = 0;
        // -------------------------------------------------
        // for each char...
        // -------------------------------------------------
        while(i_c < a_len)
        {
                switch(a_buf[i_c])
                {
                // -----------------------------------------
                // remove some characters
                // -----------------------------------------
                case '"':
                case '\'':
                case '\\':
                case '^':
                {
                        break;
                }
                // -----------------------------------------
                // replace characters w/ space (only one)
                // -----------------------------------------
                case ' ':
                case ',':
                case ';':
                case '\t':
                case '\r':
                case '\n':
                {
                        if(!l_is_space)
                        {
                                l_buf[i_j] = ' ';
                                ++i_j;
                                l_is_space = true;
                        }
                        break;
                }
                // -----------------------------------------
                // ???
                // -----------------------------------------
                case '/':
                case '(':
                {
                        // remove space before / or (
                        if(l_is_space)
                        {
                                --i_j;
                        }
                        l_is_space = false;
                        l_buf[i_j] = a_buf[i_c];
                        ++i_j;
                        break;
                }
                // -----------------------------------------
                // copy normal characters
                // -----------------------------------------
                default :
                {
                        l_buf[i_j] = tolower(a_buf[i_c]);
                        ++i_j;
                        l_is_space = false;
                        break;
                }
                }
                ++i_c;
        }
        *ao_buf = l_buf;
        ao_len = i_j;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(NORMALISEPATH)
{
        //NDBG_PRINT("...\n");
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        int32_t l_s;
        l_s = normalize_path(ao_buf, ao_len, a_buf, a_len, false);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(*ao_buf)
                {
                        free(*ao_buf);
                        *ao_buf = NULL;
                }
                ao_len = 0;
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(NORMALIZEPATH)
{
        //NDBG_PRINT("...\n");
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        int32_t l_s;
        l_s = normalize_path(ao_buf, ao_len, a_buf, a_len, false);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(*ao_buf)
                {
                        free(*ao_buf);
                        *ao_buf = NULL;
                }
                ao_len = 0;
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(NORMALIZEPATHWIN)
{
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        int32_t l_s;
        l_s = normalize_path(ao_buf, ao_len, a_buf, a_len, true);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(*ao_buf)
                {
                        free(*ao_buf);
                        *ao_buf = NULL;
                }
                ao_len = 0;
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(CSSDECODE)
{
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        int32_t l_s;
        l_s = css_decode(ao_buf, ao_len, a_buf, a_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(*ao_buf)
                {
                        free(*ao_buf);
                        *ao_buf = NULL;
                }
                ao_len = 0;
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(HTMLENTITYDECODE)
{
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        int32_t l_s;
        l_s = html_entity_decode(ao_buf, ao_len, a_buf, a_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(*ao_buf)
                {
                        free(*ao_buf);
                        *ao_buf = NULL;
                }
                ao_len = 0;
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(JSDECODE)
{
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        int32_t l_s;
        l_s = js_decode_ns(ao_buf, ao_len, a_buf, a_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(*ao_buf)
                {
                        free(*ao_buf);
                        *ao_buf = NULL;
                }
                ao_len = 0;
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(URLDECODE)
{
        //NDBG_PRINT("...\n");
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        int32_t l_s;
        uint32_t l_invalid_cnt = 0;
        l_s = urldecode_ns(ao_buf, ao_len, l_invalid_cnt, a_buf, a_len);
        UNUSED(l_invalid_cnt);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(*ao_buf)
                {
                        free(*ao_buf);
                        *ao_buf = NULL;
                }
                ao_len = 0;
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(URLDECODEUNI)
{
        //NDBG_PRINT("...\n");
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        int32_t l_s;
        l_s = urldecode_uni_ns(ao_buf, ao_len, a_buf, a_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(*ao_buf)
                {
                        free(*ao_buf);
                        *ao_buf = NULL;
                }
                ao_len = 0;
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(UTF8TOUNICODE)
{
        //NDBG_PRINT("...\n");
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        int32_t l_s;
        l_s = utf8_to_unicode(ao_buf, ao_len, a_buf, a_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(*ao_buf)
                {
                        free(*ao_buf);
                        *ao_buf = NULL;
                }
                ao_len = 0;
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(HEXENCODE)
{
        //NDBG_PRINT("...\n");
        // -------------------------------------------------
        // bytes to hex map
        // -------------------------------------------------
        static const char s_b2x[] = "0123456789abcdef";
        // -------------------------------------------------
        // check inputs
        // -------------------------------------------------
        *ao_buf = NULL;
        ao_len = 0;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // transform...
        // -------------------------------------------------
        char *l_buf = NULL;
        uint32_t l_buf_len = (2*a_len) + 1;
        l_buf = (char *)malloc(sizeof(char)*l_buf_len);
        uint32_t i_b = 0;
        for(uint32_t i_c = 0; i_c < a_len; ++i_c)
        {
                uint8_t l_c = (uint8_t)(a_buf[i_c]);
                l_buf[i_b++] = s_b2x[(l_c >> 4)];
                l_buf[i_b++] = s_b2x[(l_c & 0x0f)];
        }
        l_buf[i_b] = 0;
        *ao_buf = l_buf;
        ao_len = strnlen(l_buf, l_buf_len);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(SHA1)
{
        int32_t l_ret = WAFLZ_STATUS_OK;
        EVP_MD_CTX* l_md_ctx = NULL;
        uint32_t l_md_len = -1;
        char *l_md_val = NULL;
        int32_t l_s;
        // -------------------------------------------------
        // initialize digest context
        // -------------------------------------------------
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        l_md_ctx = EVP_MD_CTX_new();
#else
        l_md_ctx = EVP_MD_CTX_create();
#endif
        l_s = EVP_DigestInit_ex(l_md_ctx, EVP_sha1(), NULL);
        if(l_s != 1)
        {
                //ERROR("host[%s]: EVP_DigestInit_ex", a_host);
                l_ret = WAFLZ_STATUS_ERROR;
                goto cleanup;

        }
        // -------------------------------------------------
        // digest
        // -------------------------------------------------
        l_s = EVP_DigestUpdate(l_md_ctx, a_buf, a_len);
        if(l_s != 1)
        {
                //ERROR("host[%s]: EVP_DigestUpdate", a_host);
                l_ret = WAFLZ_STATUS_ERROR;
                goto cleanup;
        }
        // -------------------------------------------------
        // calculate
        // -------------------------------------------------
        l_md_val = (char *)malloc(sizeof(char)*EVP_MAX_MD_SIZE);
        l_s = EVP_DigestFinal_ex(l_md_ctx, (unsigned char *)l_md_val, &l_md_len);
        if(l_s != 1)
        {
                //ERROR("host[%s]: EVP_DigestFinal_ex", a_host);
                if(l_md_val) { delete l_md_val; l_md_val = NULL;}
                l_ret = WAFLZ_STATUS_ERROR;
                goto cleanup;

        }
        *ao_buf = l_md_val;
        ao_len = l_md_len;
cleanup:
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_md_ctx)
        {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                EVP_MD_CTX_free(l_md_ctx);
#else
                EVP_MD_CTX_destroy(l_md_ctx);
#endif
                l_md_ctx = NULL;
        }
        return l_ret;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
TX(MD5)
{
        int32_t l_ret = WAFLZ_STATUS_OK;
        EVP_MD_CTX* l_md_ctx = NULL;
        uint32_t l_md_len = -1;
        char *l_md_val = NULL;
        int32_t l_s;
        // -------------------------------------------------
        // initialize digest context
        // -------------------------------------------------
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        l_md_ctx = EVP_MD_CTX_new();
#else
        l_md_ctx = EVP_MD_CTX_create();
#endif
        l_s = EVP_DigestInit_ex(l_md_ctx, EVP_md5(), NULL);
        if(l_s != 1)
        {
                //ERROR("host[%s]: EVP_DigestInit_ex", a_host);
                l_ret = WAFLZ_STATUS_ERROR;
                goto cleanup;

        }
        // -------------------------------------------------
        // digest
        // -------------------------------------------------
        l_s = EVP_DigestUpdate(l_md_ctx, a_buf, a_len);
        if(l_s != 1)
        {
                //ERROR("host[%s]: EVP_DigestUpdate", a_host);
                l_ret = WAFLZ_STATUS_ERROR;
                goto cleanup;
        }
        // -------------------------------------------------
        // calculate
        // -------------------------------------------------
        l_md_val = (char *)malloc(sizeof(char)*EVP_MAX_MD_SIZE);
        l_s = EVP_DigestFinal_ex(l_md_ctx, (unsigned char *)l_md_val, &l_md_len);
        if(l_s != 1)
        {
                //ERROR("host[%s]: EVP_DigestFinal_ex", a_host);
                if(l_md_val) { delete l_md_val; l_md_val = NULL;}
                l_ret = WAFLZ_STATUS_ERROR;
                goto cleanup;

        }
        *ao_buf = l_md_val;
        ao_len = l_md_len;
cleanup:
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_md_ctx)
        {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                EVP_MD_CTX_free(l_md_ctx);
#else
                EVP_MD_CTX_destroy(l_md_ctx);
#endif
                l_md_ctx = NULL;
        }
        return l_ret;
}
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define INIT_TX_CB(_type) \
                s_tx_cb_vector[waflz_pb::sec_action_t_transformation_type_t_##_type] = _tx_cb_##_type
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef std::vector <tx_cb_t> tx_cb_vector_t;
//: ----------------------------------------------------------------------------
//: vector...
//: ----------------------------------------------------------------------------
static tx_cb_vector_t s_tx_cb_vector = tx_cb_vector_t(256);
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void init_tx_cb_vector(void)
{
        INIT_TX_CB(NONE);
        INIT_TX_CB(LENGTH);
        INIT_TX_CB(COMPRESSWHITESPACE);
        INIT_TX_CB(REMOVEWHITESPACE);
        INIT_TX_CB(REMOVENULLS);
        INIT_TX_CB(HEXENCODE);
        INIT_TX_CB(LOWERCASE);
        INIT_TX_CB(NORMALISEPATH);
        INIT_TX_CB(NORMALIZEPATH);
        INIT_TX_CB(REPLACECOMMENTS);
        INIT_TX_CB(REMOVECOMMENTS);
        INIT_TX_CB(NORMALIZEPATHWIN);
        INIT_TX_CB(SHA1);
        INIT_TX_CB(MD5);
        INIT_TX_CB(URLDECODEUNI);
        INIT_TX_CB(URLDECODE);
        INIT_TX_CB(HTMLENTITYDECODE);
        INIT_TX_CB(JSDECODE);
        INIT_TX_CB(CSSDECODE);
        INIT_TX_CB(CMDLINE);
        INIT_TX_CB(UTF8TOUNICODE);
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
tx_cb_t get_tx_cb(waflz_pb::sec_action_t_transformation_type_t a_type)
{
        return s_tx_cb_vector[a_type];
}
}
