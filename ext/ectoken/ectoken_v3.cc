/**
* Copyright (C) 2016 Edgecast Inc. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <assert.h>
#include <limits.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "base64.h"
#include "ectoken_v3.h"

#define G_KEY_LEN (32)
#define G_IV_LEN (12)
#define G_TAG_LEN (16)
#define G_IV_AND_TAG_LEN (G_IV_LEN+G_TAG_LEN)

namespace ns_ectoken_v3 {

unsigned int sha256(unsigned char* ao_sha, const void* a_bytes, const size_t a_len)
{
        EVP_MD_CTX *ctx;

        unsigned int l_len = -1;

        if(!(ctx = EVP_MD_CTX_create())) goto clean;

        if(1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) goto clean;

        if(1 != EVP_DigestUpdate(ctx, a_bytes, a_len)) goto clean;

        if(1 != EVP_DigestFinal_ex(ctx, ao_sha, &l_len)) goto clean;

clean:
        EVP_MD_CTX_destroy(ctx);
        return l_len;
}

int ec_encrypt(unsigned char* ao_ciphertext, size_t* ao_ciphertext_len,
               unsigned char* ao_tag,
               const unsigned char* a_plaintext, const int a_plaintext_len,
               const unsigned char* a_key,
               const unsigned char* a_iv, const size_t a_iv_len)
{
        EVP_CIPHER_CTX *l_ctx;

        int l_len;
        int l_ret = 0;

        int l_ciphertext_len = 0;

        /* Create and initialise the context */
        if(!(l_ctx = EVP_CIPHER_CTX_new()))
        {
                l_ret = -1;
                goto fail;
        }

        /* Initialise the encryption operation. */
        if(1 != EVP_EncryptInit_ex(l_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        {
                l_ret = -2;
                goto fail;
        }

        /* Set IV length if default 12 bytes (96 bits) is not appropriate */
        if(1 != EVP_CIPHER_CTX_ctrl(l_ctx, EVP_CTRL_GCM_SET_IVLEN, a_iv_len, NULL))
        {
                l_ret = -3;
                goto fail;
        }

        /* Initialise key and IV */
        if(1 != EVP_EncryptInit_ex(l_ctx, NULL, NULL, a_key, a_iv))
        {
                l_ret = -4;
                goto fail;
        }

        /* Provide the message to be encrypted, and obtain the encrypted output.
         * EVP_EncryptUpdate can be called multiple times if necessary
         */
        if(1 != EVP_EncryptUpdate(l_ctx, ao_ciphertext, &l_len, a_plaintext,
                                  a_plaintext_len))
        {
                l_ret = -5;
                goto fail;
        }
        l_ciphertext_len = l_len;

        /* Finalise the encryption. Normally ciphertext bytes may be written at
         * this stage, but this does not occur in GCM mode
         */
        if(1 != EVP_EncryptFinal_ex(l_ctx, ao_ciphertext + l_len, &l_len))
        {
                l_ret = -6;
                goto fail;
        }
        l_ciphertext_len += l_len;

        /* Get the tag */
        if(1 != EVP_CIPHER_CTX_ctrl(l_ctx, EVP_CTRL_GCM_GET_TAG, 16, ao_tag))
        {
                l_ret = -7;
                goto fail;
        }

        *ao_ciphertext_len = l_ciphertext_len;
        goto clean;

fail:
        OPENSSL_cleanse(ao_ciphertext, *ao_ciphertext_len);

clean:
        /* Clean up */
        EVP_CIPHER_CTX_free(l_ctx);

        return l_ret;
}

int ec_decrypt(unsigned char* ao_plaintext, size_t* a_plaintext_len,
               const unsigned char* a_ciphertext, const size_t a_ciphertext_len,
               const unsigned char* a_key, const unsigned char* a_iv,
               const int a_iv_len, unsigned char* a_tag,
               const int a_tag_len)
{
        EVP_CIPHER_CTX *l_ctx;
        int l_len = 0;
        size_t l_plaintext_len;
        int l_ret = 0;

        /* Create and initialise the context */
        if(!(l_ctx = EVP_CIPHER_CTX_new()))
        {
                l_ret = -1;
                goto fail;
        }

        /* Initialise the decryption operation. */
        if(!EVP_DecryptInit_ex(l_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        {
                l_ret = -2;
                goto fail;
        }

        /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
        if(!EVP_CIPHER_CTX_ctrl(l_ctx, EVP_CTRL_GCM_SET_IVLEN, a_iv_len, NULL))
        {
                l_ret = -3;
                goto fail;
        }

        /* Initialise key and IV */
        if(!EVP_DecryptInit_ex(l_ctx, NULL, NULL, a_key, a_iv))
        {
                l_ret = -4;
                goto fail;
        }

        /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
        if(!EVP_CIPHER_CTX_ctrl(l_ctx, EVP_CTRL_GCM_SET_TAG, a_tag_len, a_tag))
        {
                l_ret = -5;
                goto fail;
        }

        /* Provide the message to be decrypted, and obtain the plaintext output.
         * EVP_DecryptUpdate can be called multiple times if necessary
         */
        if(!EVP_DecryptUpdate(l_ctx,
                              ao_plaintext, &l_len, a_ciphertext,
                              a_ciphertext_len))
        {
                l_ret = -6;
                goto fail;
        }
        l_plaintext_len = l_len;

        /* Finalise the decryption. A positive return value indicates success,
         * anything else is a clean - the plaintext is not trustworthy.
         */
        if(!EVP_DecryptFinal_ex(l_ctx, ao_plaintext + l_len, &l_len))
        {
                l_ret = -7;
                goto fail;
        }
        goto clean;
fail:
        OPENSSL_cleanse(ao_plaintext, *a_plaintext_len);
clean:
        EVP_CIPHER_CTX_free(l_ctx);

        if(l_ret == 0)
        {
                /* Success */
                l_plaintext_len += l_len;
                *a_plaintext_len = l_plaintext_len;
        }
        return l_ret;
}

int generate_iv(unsigned char* ao_iv, const int a_iv_len)
{
        OPENSSL_cleanse(ao_iv, a_iv_len);
        if (RAND_bytes(ao_iv, a_iv_len) != 1)
                return -1;

        return 0;
}

static const char s_alphanum[] =
"-_0123456789"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz";
/* Note that we -1 to account for the trailing 0x0 */
static const int s_alphanum_len = sizeof(s_alphanum)/sizeof(s_alphanum[0])-1;

int generate_nonce(unsigned char* ao_nonce, int* ao_nonce_len)
{
        int i;
        int ret = 0;
        /* l_rand_bytes[0] % 4 + 4 determines the actual l_nonce_len we use */
        int l_nonce_len = 9;
        unsigned char l_rand_bytes[l_nonce_len];

        OPENSSL_cleanse(l_rand_bytes, l_nonce_len);
        if (RAND_bytes(l_rand_bytes, l_nonce_len) != 1)
        {
                ret = -1;
                goto clean;
        }

        /* Generate a number in [4,8].
         * This *only* works because UCHAR_MAX+1 % 4 == 0
         */
        l_nonce_len = l_rand_bytes[0] % 4 + 4;

        /* This *only* works if (UCHAR_MAX+1) % s_alphanum_len == 0
         * http://ericlippert.com/2013/12/16/how-much-bias-is-introduced-by-the-remainder-technique/
         * We start at 1 and go to l_nonce_len+1 because the first byte of
         * l_rand_bytes determined l_nonce_len
         */
        for (i = 1; i < l_nonce_len+1; ++i)
        {
                /* Inplace change l_rand_bytes[i] to be in s_alphanum. */
                l_rand_bytes[i] = s_alphanum[l_rand_bytes[i] % s_alphanum_len];
        }
        *ao_nonce_len = l_nonce_len;
        memcpy(ao_nonce, l_rand_bytes+1, l_nonce_len);

        /* Cleanup the memory used for our nonce. */
clean:
        OPENSSL_cleanse(l_rand_bytes, l_nonce_len);

        return ret;
}

int construct_base64_encoded_token(unsigned char* ao_encoded_message,
                                   size_t* ao_encoded_message_len,
                                   const unsigned char* a_iv,
                                   const int a_iv_len,
                                   const unsigned char* a_tag,
                                   const int a_tag_len,
                                   const unsigned char* a_ciphertext,
                                   const int a_ciphertext_len)

{
        size_t l_len = a_iv_len+a_tag_len+a_ciphertext_len;
        size_t l_encoded_len = base64_encoded_size(l_len);;
        if (*ao_encoded_message_len < l_encoded_len)
        {
                return -1;
        }

        unsigned char l_scratch[l_len+1];
        memset(l_scratch, 0, l_len);
        memcpy(l_scratch, a_iv, a_iv_len);
        memcpy(l_scratch+a_iv_len, a_ciphertext, a_ciphertext_len);
        memcpy(l_scratch+a_iv_len+a_ciphertext_len, a_tag, a_tag_len);
        l_scratch[l_len] = 0x0;

        *ao_encoded_message_len = base64_encode((char*)ao_encoded_message, (char*)l_scratch, l_len);
        ao_encoded_message[*ao_encoded_message_len] = 0x0;

        OPENSSL_cleanse(l_scratch, l_len);
        return 0;
}

int deconstruct_base64_encoded_token(unsigned char* ao_token,
                                     unsigned char* ao_iv, const int a_iv_len,
                                     unsigned char* ao_tag, const int a_tag_len,
                                     const unsigned char* b64_encoded_str,
                                     const int b64_encoded_str_len)
{
        int l_len = base64_decode_binary(ao_token, (char*) b64_encoded_str,
                                         b64_encoded_str_len);
        if (l_len == -1)
        {
                return -1;
        }

        memcpy(ao_tag, ao_token+(l_len-a_tag_len), a_tag_len);
        memcpy(ao_iv, ao_token, a_iv_len);

        /* Reusing ao_token lets us avoid a malloc and copy */
        memmove(ao_token, ao_token+a_iv_len, l_len-a_iv_len-a_tag_len);
        memset(ao_token+(l_len-a_tag_len-a_iv_len), 0, a_iv_len+a_tag_len);

        l_len = l_len-a_iv_len-a_tag_len;

        return l_len;
}

//! @brief  Initialize the system for encrypting and decrypting ectoken tokens
//! @return 0 on success
//!         -1 on failure
int ectoken_init()
{
        if (RAND_status() == 0)
        {
                RAND_poll();
                if (RAND_status() == 0)
                {
                        /* Could not prepare openssl RNG */
                        return -1;
                }
        }
        return 0;
}

//! @brief  Returns the size a buffer needs to be to contain a valid token
//! @return the size of an encrypted, base64 encoded token, with space for a null termination byte
size_t ectoken_encrypt_required_size(const size_t a_length)
{
        return base64_encoded_size(a_length + G_IV_AND_TAG_LEN) + 1;
}

//! @brief  Returns the size a buffer needs to be to contain a valid token
//! @return the size of decrypted token. Will always be at *least* one longer than the final decrypted token or 0 if a_length is too short to be a valid token.
size_t ectoken_decrypt_required_size(const size_t a_length)
{
        const size_t l_decoded_len = base64_decoded_size(a_length);
        if (l_decoded_len <= G_IV_AND_TAG_LEN)
                return 0;
        return  l_decoded_len - G_IV_AND_TAG_LEN + 1;
}


//! @brief   Decrypt and internally validate a provided token
//! @details This function performs decryption and cryptographic validation of the provided token
//! @return  0 on success
//!          -1 on failure to decrypt the token
//!          -2 on failure to validate the cryptographic tag
//!          -3 when provided with invalid arguments
//! @param   ao_plaintext     The output argument that is populated with the plaintext value. Should be a_token_len bytes.
//! @param   ao_plaintext_len This argument should initially point to an integer specifying the size of the buffer at ao_plaintext.
//!                           On function exit the integer will be set to the length of the decrypted token
//! @param   a_token          A pointer to the ciphertext
//! @param   a_token_len      The length of the provided ciphertext. 1 <= a_token_len <= 6144
//! @param   a_key            A pointer to the key to use to decrypt. Should be securely generated and at least 32 bytes long.
//! @param   a_key_len        The length of the provided key. 1 <= a_key_len <= 4096
int ectoken_decrypt_token(char* ao_plaintext, size_t* ao_plaintext_len,
                          const char* a_token, const size_t a_token_len,
                          const char* a_key, const size_t a_key_len)
{

        if(!ao_plaintext     ||
           !ao_plaintext_len ||
           !a_token          ||
           !a_token_len      ||
           !a_key            ||
           !a_key_len)
                return -3;

        if(a_token_len > 6144 ||
           a_token_len < 0    ||
           a_key_len   > 4096 ||
           a_key_len   < 0)
                return -3;

        if(ectoken_encrypt_required_size(0) > a_token_len)
                return -3;
        if(ectoken_decrypt_required_size(a_token_len) > *ao_plaintext_len)
                return -3;

        memset(ao_plaintext, 0, *ao_plaintext_len);

        int l_ret = 0;
        int l_ciphertext_len = a_token_len;

        unsigned char l_ciphertext[l_ciphertext_len];
        unsigned char l_iv[G_IV_LEN];
        unsigned char l_tag[G_TAG_LEN];
        unsigned char l_key[G_KEY_LEN];
        size_t l_token_len = a_token_len;
        unsigned char l_token[l_token_len];
        memset(l_token, 0, l_token_len);

        l_ret = sha256(l_key, a_key, a_key_len);
        if (l_ret < 32)
        {
                l_ret = -3;
                goto cleanup;
        }

        l_ciphertext_len = deconstruct_base64_encoded_token(l_ciphertext,
                                                            l_iv, G_IV_LEN,
                                                            l_tag, G_TAG_LEN,
                                                            (unsigned char*) a_token,
                                                            a_token_len);
        if (l_ciphertext_len <= 0)
        {
                return -1;
        }

        l_ret = ec_decrypt(l_token, &l_token_len,
                           l_ciphertext, l_ciphertext_len,
                           (unsigned char*)l_key,
                           l_iv, G_IV_LEN,
                           l_tag, G_TAG_LEN);
        switch (l_ret)
        {
                case 0:
                        break;
                case -7:
                        l_ret = -2;
                        goto cleanup;
                        break;
                case -1:
                case -2:
                case -3:
                case -4:
                case -5:
                case -6:
                default:
                        l_ret = -1;
                        goto cleanup;
                        break;
        }

        if (l_token_len > *ao_plaintext_len)
        {
                // something went wrong with our earlier calculations for
                // length, but we know here that we must never blow past the
                // original length
                l_ret = -3;
                goto cleanup;
        }

        memcpy(ao_plaintext, l_token, l_token_len);
        ao_plaintext[l_token_len] = 0x0;
        *ao_plaintext_len = l_token_len;

cleanup:
        OPENSSL_cleanse(l_key, G_KEY_LEN);
        OPENSSL_cleanse(l_iv, G_IV_LEN);
        OPENSSL_cleanse(l_tag, G_TAG_LEN);
        OPENSSL_cleanse(l_ciphertext, l_ciphertext_len);
        OPENSSL_cleanse(l_token, l_token_len);

        return l_ret;
}


//! @brief   Encrypt and internally validate a provided token
//! @details This function performs encryptiong and cryptographic validation of the provided token
//! @return  0 on success
//!          -1 on failure to encrypt the token
//!          -2 on failure to gather the cryptographic tag
//!          -3 when provided with invalid arguments
//! @param   ao_token         The output argument that is populated with the token value. Should be at least ectoken_encrypt_required_size(a_plaintext_len).
//! @param   ao_token_len     This argument should initially point to an integer specifying the size of the buffer at ao_token.
//!                           Should be at least ectoken_encrypt_required_size(a_plaintext_len).
//!                           On function exit the integer will be set to the length of the encrypted token
//! @param   a_plaintext      A pointer to the ciphertext
//! @param   a_plaintext_len  The length of the provided ciphertext. Should be less than 4096.
//! @param   a_key            A pointer to the key to use to encrypt. Should be securely generated and at least 32 bytes long.
//! @param   a_key_len        The length of the provided key. 1 <= a_key_len <= 4096
int ectoken_encrypt_token(char* ao_token, size_t* ao_token_len,
                          const char* a_plaintext, const size_t a_plaintext_len,
                          const char* a_key, const size_t a_key_len)
{
        if(!ao_token        ||
           !ao_token_len    ||
           !a_plaintext     ||
           !a_plaintext_len ||
           !a_key           ||
           !a_key_len)
                return -3;

        if(a_plaintext_len > 4096 ||
           a_plaintext_len < 0    ||
           a_key_len       > 4096 ||
           a_key_len       < 0    ||
           *ao_token_len   < 0)
                return -3;

        if(*ao_token_len < ectoken_encrypt_required_size(a_plaintext_len))
                return -3;

        int l_ret = 0;

        size_t l_ciphertext_len = a_plaintext_len;
        unsigned char l_ciphertext[l_ciphertext_len];
        unsigned char l_iv[G_IV_LEN];
        unsigned char l_tag[G_TAG_LEN];
        unsigned char l_key[G_KEY_LEN];

        l_ret = sha256(l_key, a_key, a_key_len);
        if (l_ret < 32)
        {
                l_ret = -3;
                goto cleanup;
        }

        if (generate_iv(l_iv, G_IV_LEN) != 0)
        {
                l_ret = -1;
                goto cleanup;
        }
        l_ret = ec_encrypt(l_ciphertext, &l_ciphertext_len,
                           l_tag,
                           (unsigned char*) a_plaintext, a_plaintext_len,
                           (unsigned char*) l_key,
                           l_iv, G_IV_LEN);

        switch (l_ret)
        {
        case 0:
                break;
        case -7: /* Failed to get the tag. */
                l_ret = -2;
                goto cleanup;
                break;
        case -1: /* Failed to initialize the context. */
        case -2: /* Failed to initialize the crypto operation. */
        case -3: /* Failed to set IV length. */
        case -4: /* Failed to set key and IV. */
        case -5: /* Failed to encrypt the message. */
        case -6: /* Failed to finalize the encryption. */
        default:
                l_ret = -1;
                goto cleanup;
                break;
        }

        construct_base64_encoded_token((unsigned char*)ao_token, ao_token_len,
                                       l_iv, G_IV_LEN,
                                       l_tag, G_TAG_LEN,
                                       (unsigned char*) l_ciphertext,
                                       l_ciphertext_len);
cleanup:
        OPENSSL_cleanse(l_key, G_KEY_LEN);
        OPENSSL_cleanse(l_iv, G_IV_LEN);
        OPENSSL_cleanse(l_tag, G_TAG_LEN);
        OPENSSL_cleanse(l_ciphertext, l_ciphertext_len);

        return l_ret;
}

}
