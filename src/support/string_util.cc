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
//! Includes
//! ----------------------------------------------------------------------------
#include "support/ndebug.h"
#include "waflz/def.h"
#include "waflz/string_util.h"
#include <limits.h>
#include <string.h>
#include <regex.h>
#include <stdlib.h>
#include <errno.h>
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
std::string get_file_wo_path(const std::string &a_filename)
{
        std::string fName(a_filename);
        size_t pos = fName.rfind("/");
        if(pos == std::string::npos)  //No extension.
                return fName;
        if(pos == 0)    //. is at the front. Not an extension.
                return fName;
        return fName.substr(pos + 1, fName.length());
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
std::string get_file_path(const std::string &a_filename)
{
        std::string fName(a_filename);
        size_t pos = fName.rfind("/");
        if(pos == std::string::npos)  //No extension.
                return fName;
        if(pos == 0)    //. is at the front. Not an extension.
                return fName;
        return fName.substr(0, pos);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
std::string get_base_filename(const std::string &a_filename)
{
        std::string fName(a_filename);
        size_t pos = fName.rfind(".");
        if(pos == std::string::npos)  //No extension.
                return fName;
        if(pos == 0)    //. is at the front. Not an extension.
                return fName;
        return fName.substr(0, pos);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
std::string get_file_ext(const std::string &a_filename)
{
        std::string fName(a_filename);
        size_t pos = fName.rfind(".");
        if(pos == std::string::npos)  //No extension.
                return NULL;
        if(pos == 0)    //. is at the front. Not an extension.
                return NULL;
        return fName.substr(pos + 1, fName.length());
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
std::string get_file_wo_ext(const std::string &a_filename)
{
        std::string fName(a_filename);
        size_t pos = fName.rfind(".");
        if(pos == std::string::npos)  //No extension.
                return NULL;
        if(pos == 0)    //. is at the front. Not an extension.
                return NULL;
        return fName.substr(0, pos);
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return: TODO
//! \param:  TODO
//! ----------------------------------------------------------------------------
int32_t convert_hex_to_uint(uint64_t &ao_val, const char *a_str)
{
        ao_val = strtoull(a_str, NULL, 16);
        if((ao_val == ULLONG_MAX) ||
           (ao_val == 0))
        {
                ao_val = 0;
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Find the first occurrence of find in s, where the search is limited
//!          to the first slen characters of s.
//! \return  TODO
//! \param   TODO
//! \notes   strnstr from freebsd
//! ----------------------------------------------------------------------------
char *strnstr(const char *s, const char *find, size_t slen)
{
        if(!s ||
           !find ||
           !slen)
        {
                return NULL;
        }
        char c;
        char sc;
        size_t len;
        if((c = *find++) != '\0')
        {
                len = strlen(find);
                do
                {
                        do
                        {
                                if (slen-- < 1 || (sc = *s++) == '\0')
                                {
                                        return (NULL);
                                }
                        } while (sc != c);
                        if(len > slen)
                        {
                                return (NULL);
                        }
                } while (strncmp(s, find, len) != 0);
                s--;
        }
        return ((char *)s);
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
long int strntol(const char *a_str, size_t a_size, char **ao_end, int a_base)
{
        char l_buf[24];
        long int l_ret;
        const char *l_begin = a_str;
        // catch up leading spaces
        for(; l_begin && a_size && (*l_begin == ' '); ++l_begin, --a_size);
        if(!a_size || a_size >= sizeof(l_buf))
        {
                if(ao_end)
                {
                        *ao_end = (char *)a_str;
                }
                return LONG_MIN;
        }
        memcpy(l_buf, l_begin, a_size);
        l_buf[a_size] = '\0';
        errno = 0;
        l_ret = strtol(l_buf, ao_end, a_base);
        if((l_ret == LONG_MIN) ||
           (l_ret == LONG_MAX))
        {
                return l_ret;
        }
        if(ao_end)
        {
                *ao_end = (char *) a_str + (*ao_end - l_buf);
        }
        return l_ret;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int64_t strntoll(const char *a_str, size_t a_size, char **ao_end, int a_base)
{
        char l_buf[24];
        int64_t l_ret;
        const char *l_begin = a_str;
        // catch up leading spaces
        for(; l_begin && a_size && (*l_begin == ' '); ++l_begin, --a_size);
        if(!a_size || a_size >= sizeof(l_buf))
        {
                if(ao_end)
                {
                        *ao_end = (char *)a_str;
                }
                return (int64_t)LLONG_MIN;
        }
        memcpy(l_buf, l_begin, a_size);
        l_buf[a_size] = '\0';
        l_ret = strtoll(l_buf, ao_end, a_base);
        if((l_ret == LLONG_MIN) ||
           (l_ret == LLONG_MAX))
        {
                return l_ret;
        }
        if(ao_end)
        {
                *ao_end = (char *) a_str + (*ao_end - l_buf);
        }
        return l_ret;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
unsigned long int strntoul(const char *a_str, size_t a_size, char **ao_end, int a_base)
{
        char l_buf[24];
        unsigned long int l_ret;
        const char *l_begin = a_str;
        // catch up leading spaces
        for(; l_begin && a_size && (*l_begin == ' '); ++l_begin, --a_size);
        if(!a_size || a_size >= sizeof(l_buf))
        {
                if(ao_end)
                {
                        *ao_end = (char *)a_str;
                }
                return (uint32_t)ULONG_MAX;
        }
        memcpy(l_buf, l_begin, a_size);
        l_buf[a_size] = '\0';
        l_ret = strtoul(l_buf, ao_end, a_base);
        if(l_ret == ULONG_MAX)
        {
                return l_ret;
        }
        if(ao_end)
        {
                *ao_end = (char *) a_str + (*ao_end - l_buf);
        }
        return l_ret;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
uint64_t strntoull(const char *a_str, size_t a_size, char **ao_end, int a_base)
{
        char l_buf[24];
        uint64_t l_ret;
        const char *l_begin = a_str;
        // catch up leading spaces
        for(; l_begin && a_size && (*l_begin == ' '); ++l_begin, --a_size);
        if(!a_size || a_size >= sizeof(l_buf))
        {
                if(ao_end)
                {
                        *ao_end = (char *)a_str;
                }
                return (uint64_t)ULLONG_MAX;
        }
        memcpy(l_buf, l_begin, a_size);
        l_buf[a_size] = '\0';
        l_ret = strtoull(l_buf, ao_end, a_base);
        if(l_ret == ULLONG_MAX)
        {
                return l_ret;
        }
        if(ao_end)
        {
                *ao_end = (char *) a_str + (*ao_end - l_buf);
        }
        return l_ret;
}
//! ----------------------------------------------------------------------------
//! \details Appends src to string dst of size dsize
//!          (unlike strncat, dsize is full size of dst, not space left).
//!          At most dsize-1 characters will be copied.
//!          Always NULL terminates (unless dsize <= strlen(dst)).
//! \return  strlen(src) + MIN(dsize, strlen(initial dst)).
//!          If retval >= dsize, truncation occurred.
//! \param   TODO
//! ----------------------------------------------------------------------------
size_t strlcat(char *a_dst, const char *a_src, size_t a_dsize)
{
        const char *l_odst = a_dst;
        const char *l_osrc = a_src;
        size_t l_n = a_dsize;
        size_t l_dlen;
        // -------------------------------------------------
        // Find the end of a_dst and adjust bytes left but
        /// don't go past end.
        // -------------------------------------------------
        while(l_n-- != 0 &&
              *a_dst != '\0')
        {
                ++a_dst;
        }
        l_dlen = a_dst - l_odst;
        l_n = a_dsize - l_dlen;
        if (l_n-- == 0)
        {
                return(l_dlen + strlen(a_src));
        }
        while (*a_src != '\0')
        {
                if (l_n != 0)
                {
                        *a_dst++ = *a_src;
                        l_n--;
                }
                ++a_src;
        }
        *a_dst = '\0';
        // -------------------------------------------------
        // count does not include NULL
        // -------------------------------------------------
        return(l_dlen + (a_src - l_osrc));
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t convert_to_lower_case(char** ao_out, size_t& ao_len, const char* a_src, size_t a_len)
{
        if(!a_src ||!a_len ||!ao_out)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_out = NULL;
        ao_len = 0;
        char* l_buf= NULL;
        l_buf = (char*)malloc(a_len+1);
        l_buf[a_len] = '\0';
        for(uint32 i = 0; i < a_len ; ++i)
        {
                l_buf[i] = tolower((int)a_src[i]);
        }
        *ao_out = l_buf;
        ao_len = a_len;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
#if defined(__APPLE__) || defined(__darwin__)
void * memrchr(const void *s, int c, size_t n)
{
    const unsigned char *cp;
    if (n != 0) {
            cp = (unsigned char *)s + n;
            do
            {
                    if (*(--cp) == (unsigned char)c)
                    return (void *)cp;
            }while (--n != 0);
    }
    return (void *)0;
}
#endif
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
typedef struct {
        char m_token[32];
        char m_color[32];
} token_color_t;
const token_color_t g_token_color_map[] = {
        {"id:",   ANSI_COLOR_FG_YELLOW},
        {"msg:",  ANSI_COLOR_FG_GREEN},
        {"file:", ANSI_COLOR_FG_CYAN},
};
#define TOKEN_COLOR_MAP_LEN (sizeof(g_token_color_map)/sizeof(g_token_color_map[0]))
regex_t g_regex;
bool g_regex_initialized = false;
int32_t colorize_string(std::string &ao_string)
{
        int reti = 0;
        regmatch_t pmatch[1];
        uint32_t l_last_offt = 0;
        if(!g_regex_initialized)
        {
                reti = regcomp(&g_regex, "[[:space:]][A-Za-z0-9_]+:", REG_EXTENDED);
                if( reti ){ fprintf(stderr, "Could not compile regex\n"); return -1; }
                g_regex_initialized = true;
        }
        const char *l_str_ptr = ao_string.data();
        while(regexec(&g_regex, l_str_ptr, 1, pmatch, 0) == 0)
        {
                //printf("Match reti = %d --pmatch = %d --> %d\n", reti, pmatch[0].rm_so, pmatch[0].rm_eo);
                uint32_t l_match_start = pmatch[0].rm_so + l_last_offt;
                uint32_t l_match_end = pmatch[0].rm_eo + l_last_offt;
                const char *l_search_ptr = ao_string.data() + l_match_start + 1 + strlen(ANSI_COLOR_FG_BLUE);
                ao_string.insert(l_match_start, ANSI_COLOR_FG_BLUE);
                ao_string.insert((l_match_end + strlen(ANSI_COLOR_FG_BLUE)), ANSI_COLOR_OFF);
                // Check for symbol and name
                uint32_t i_token;
                for(i_token = 0; i_token < TOKEN_COLOR_MAP_LEN; ++i_token)
                {
                        if(strncmp(l_search_ptr,
                                   g_token_color_map[i_token].m_token,
                                   strlen(g_token_color_map[i_token].m_token)) == 0)
                        {
                                ao_string.insert((l_match_end + strlen(ANSI_COLOR_FG_BLUE) + strlen(ANSI_COLOR_OFF)),
                                                g_token_color_map[i_token].m_color);
                                l_last_offt+= strlen(g_token_color_map[i_token].m_color);
                        }
                }
                l_last_offt+= (pmatch[0].rm_eo) + strlen(ANSI_COLOR_BG_BLUE) + strlen(ANSI_COLOR_OFF);
                l_str_ptr = (char *)(ao_string.data() + l_last_offt);
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: return version string
//! \return:  version string
//! ----------------------------------------------------------------------------
const char *get_version(void)
{
        return WAFLZ_VERSION;
}
}
