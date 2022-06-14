//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    nms.cc
//: \details: TODO
//: \author:  Robert J. Peters
//: \date:    01/01/2014
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
#include "nms.h"
#include <arpa/inet.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#ifndef WAFLZ_STATUS_OK
  #define WAFLZ_STATUS_OK 0
#endif
#ifndef WAFLZ_STATUS_ERROR
  #define WAFLZ_STATUS_ERROR -1
#endif
#ifndef WAFLZ_ERR_LEN
  #define WAFLZ_ERR_LEN 4096
#endif

#if defined(__APPLE__) || defined(__darwin__)
/* OSX seems not to define these. */
#ifndef s6_addr16
#define s6_addr16 __u6_addr.__u6_addr16
#endif
#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif
#endif
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#ifndef NDBG_OUTPUT
#define NDBG_OUTPUT(...) \
        do { \
                fprintf(stdout, __VA_ARGS__); \
                fflush(stdout); \
        } while(0)
#endif
#ifndef NDBG_PRINT
#define NDBG_PRINT(...) \
        do { \
                fprintf(stdout, "%s:%s.%d: ", __FILE__, __FUNCTION__, __LINE__); \
                fprintf(stdout, __VA_ARGS__);               \
                fflush(stdout); \
        } while(0)
#endif
#ifndef WAFLZ_PERROR
#define WAFLZ_PERROR(_str, ...) do { \
  snprintf(_str, WAFLZ_ERR_LEN, "%s.%s.%d: ",__FILE__,__FUNCTION__,__LINE__); \
  int _len = strlen(_str); \
  snprintf(_str + _len, WAFLZ_ERR_LEN - _len, __VA_ARGS__); \
} while(0)
#endif
namespace ns_waflz
{
//: ----------------------------------------------------------------------------
//: ****************************************************************************
//:                          N E T M A S K   S E T
//: ****************************************************************************
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
nms::nms():
        ipv4_arr(new ipv4_set_t[33]),
        ipv6_arr(new ipv6_set_t[129])
{}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
nms::~nms()
{
        if(ipv4_arr) { delete[] ipv4_arr; ipv4_arr = NULL;}
        if(ipv6_arr) { delete[] ipv6_arr; ipv6_arr = NULL;}
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t nms::add(const char *a_buf, uint32_t a_buf_len)
{
        // -------------------------------------------------
        // detect type
        // -------------------------------------------------
        // TODO -address type detection is crude
        if(strchr(a_buf, ':') == NULL)
        {
                return add_ipv4(a_buf, a_buf_len);
        }
        return add_ipv6(a_buf, a_buf_len);
#if 0
        // -------------------------------------------------
        // detect type
        // -------------------------------------------------
        ip_tree::addr_t l_addr = ip_tree::ADDR_NONE;
        l_addr = detect_addr(a_buf, a_buf_len);
        if(l_addr == ip_tree::ADDR_NONE)
        {
                WAFLZ_PERROR(m_err_msg, "invalid ipv address: %.*s",
                             a_buf_len, a_buf);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // add
        // -------------------------------------------------
        switch(l_addr)
        {
        case ip_tree::ADDR_IPV4:
        {
                return add_ipv4(a_buf, a_buf_len);
        }
        case ip_tree::ADDR_IPV6:
        {
                return add_ipv6(a_buf, a_buf_len);
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg, "invalid address type: %d", l_addr);
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_ERROR;
#endif
}
//Helper
#if 0
int32_t nms::print_map()
{
        NDBG_PRINT("ipv4 map\n");
        TRC_DEBUG("ipv4 map\n");
        NDBG_PRINT("Size:: %lu\n", m_ipv4_mask_map->size());
        TRC_DEBUG("Size:: %lu\n", m_ipv4_mask_map->size());
        for (ipv4_mask_map_t::iterator i_t = m_ipv4_mask_map->begin(); i_t  != m_ipv4_mask_map->end(); ++i_t)
        {
                ipv4_set_t::iterator i_s_t;
                for(i_s_t = i_t->second.begin(); i_s_t != i_t->second.end(); ++i_s_t)
                {
                        struct in_addr l_t;
                        l_t.s_addr = *i_s_t;
                        NDBG_PRINT("%d   ::  %s\n", i_t->first, inet_ntoa(l_t));
                        TRC_DEBUG("%d   ::  %s\n", i_t->first, inet_ntoa(l_t));
                }
        }
        return WAFLZ_STATUS_OK;
}
#endif
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t nms::contains(bool &ao_match, const char *a_buf, uint32_t a_buf_len)
{
        if(strchr(a_buf, ':') == NULL)
        {
                return contains_ipv4(ao_match, a_buf, a_buf_len);
        }
        return contains_ipv6(ao_match, a_buf, a_buf_len);
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
nms::addr_t nms::detect_addr(const char *a_buf, uint32_t a_buf_len)
{
        nms::addr_t l_addr = nms::ADDR_NONE;
        int l_s;
        if(memchr(a_buf, a_buf_len, ':') == NULL)
        {
                struct in_addr l_in;
                l_s = inet_pton(AF_INET, a_buf, &l_in);
                if(l_s > 0)
                {
                        l_addr = nms::ADDR_IPV4;
                }
        }
        else
        {
                struct in6_addr l_in6;
                l_s = inet_pton(AF_INET6, a_buf, &l_in6);
                if(l_s > 0)
                {
                        l_addr = nms::ADDR_IPV6;
                }
        }
        return l_addr;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t nms::add_ipv4_plain(const char *a_buf, uint32_t a_buf_len)
{
        struct in_addr l_in;
        int l_s;
        l_s = inet_pton(AF_INET, a_buf, &l_in);
        if(l_s != 1)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        if(!ipv4_arr)
        {
                ipv4_arr = new ipv4_set_t[33];
        }
        bool l_match=false;
        // -------------------------------------------------
        // If ipv4 already contained, dont add
        // -------------------------------------------------
        if(contains_ipv4(l_match,a_buf,a_buf_len)!=WAFLZ_STATUS_OK) {
                return WAFLZ_STATUS_ERROR;
        }
        if(l_match) {
                return WAFLZ_STATUS_OK;
        }
        ipv4_arr[32].insert(l_in.s_addr);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t nms::add_ipv4_cidr(const char *a_buf, uint32_t a_buf_len)
{
        // -------------------------------------------------
        // find slash
        // -------------------------------------------------
        char *l_slash_pos = (char *)memchr(a_buf, '/', a_buf_len);
        if(l_slash_pos[1] == '\0')
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get bits
        // -------------------------------------------------
        char* l_err = NULL;
        uint32_t l_bits;
        l_bits = strtoul(l_slash_pos + 1, &l_err, 10);
        if(*l_err ||
           (l_bits == ULONG_MAX))
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        if(l_bits > 32)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // build netmask
        // -------------------------------------------------
        uint32_t l_mask;
        l_mask = (l_bits == 0) ? 0 : htonl(~((1 << (32 - l_bits)) - 1));
        // -------------------------------------------------
        // get truncated string
        // -------------------------------------------------
        char l_nm_ip[64];
        if ((size_t)(l_slash_pos - a_buf) >= (sizeof(l_nm_ip)-1))
        {
                // netmask too long
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        strncpy(l_nm_ip, a_buf, l_slash_pos - a_buf);
        l_nm_ip[l_slash_pos - a_buf] = '\0';
        // -------------------------------------------------
        // convert to ipaddr
        // -------------------------------------------------
        struct in_addr l_in;
        int l_s;
        l_s = inet_pton(AF_INET, l_nm_ip, &l_in);
        if(l_s != 1)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create masked address
        // -------------------------------------------------
        uint32_t l_masked_addr = l_in.s_addr & l_mask;
        // -------------------------------------------------
        // create sets if not already created
        // -------------------------------------------------
        if(!ipv4_arr)
        {
                ipv4_arr = new ipv4_set_t[33];
        }
        // ----------------------------------------
        // iterate through to handle redundancies
        // ----------------------------------------
        for(int i = 0 ;i<33;++i) {
                int32_t temp_mask = (i == 0) ? 0 : htonl(~((1 << (32 - i))-1 ));
                // ----------------------------------------
                // Check if prefix of prefix is already in 
                // nms
                // ----------------------------------------
                if(i<l_bits && ipv4_arr[i].find(l_masked_addr & temp_mask)!=ipv4_arr[i].end()) {
                        break;
                }
                // ----------------------------------------
                // check to find all CIDRs and IPs matching
                // this prefix and delete
                // ----------------------------------------
                if(i>l_bits) {
                        std::set<in_addr_t>::iterator itr = ipv4_arr[i].lower_bound(l_masked_addr);
                        while(itr!=ipv4_arr[i].end()) {
                                if((*itr & l_mask) == l_masked_addr) {
                                        itr = ipv4_arr[i].erase(itr);
                                        continue;
                                }
                                break;
                        }
                }
        }
        // ----------------------------------------
        // add
        // ----------------------------------------
        ipv4_arr[l_bits].insert(l_masked_addr);
        return WAFLZ_STATUS_OK;
}
//: ------------------------------------------------------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ------------------------------------------------------------------------------------------------------------------------
int32_t nms::add_ipv4(const char *a_buf, uint32_t a_buf_len)
{
        if(memchr(a_buf, '/', a_buf_len) == NULL)
        {
                return add_ipv4_plain(a_buf, a_buf_len);
        }
        return add_ipv4_cidr(a_buf, a_buf_len);
}
//: ------------------------------------------------------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ------------------------------------------------------------------------------------------------------------------------
int32_t nms::add_ipv6_plain(const char *a_buf, uint32_t a_buf_len)
{
        struct in6_addr l_in6;
        int l_s;
        l_s = inet_pton(AF_INET6, a_buf, &l_in6);
        if(l_s != 1)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        if(!ipv6_arr)
        {
                ipv6_arr = new ipv6_set_t[129];
        }
        bool l_match=false;
        // -------------------------------------------------
        // If IPv6 already contained, don't add
        // -------------------------------------------------
        if(contains_ipv6(l_match,a_buf,a_buf_len)!=WAFLZ_STATUS_OK) {
                return WAFLZ_STATUS_ERROR;
        }
        if(l_match) {
                return WAFLZ_STATUS_OK;
        }
        ipv6_arr[128].insert(l_in6);
        return WAFLZ_STATUS_OK;
}
//: ------------------------------------------------------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ------------------------------------------------------------------------------------------------------------------------
int32_t nms::add_ipv6_cidr(const char *a_buf, uint32_t a_buf_len)
{
        // --------------------------------------------------------------------------------
        // find slash
        // --------------------------------------------------------------------------------
        char *l_slash_pos = (char *)memchr(a_buf, '/', a_buf_len);
        if(l_slash_pos[1] == '\0')
        {
                return WAFLZ_STATUS_ERROR;
        }
        // --------------------------------------------------------------------------------
        // get bits
        // --------------------------------------------------------------------------------
        char* l_err = NULL;
        uint32_t l_bits;
        l_bits = strtoul(l_slash_pos + 1, &l_err, 10);
        if(*l_err ||
           (l_bits == ULONG_MAX))
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        if(l_bits > 128)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // build netmask
        // -------------------------------------------------
        in6_addr l_mask;
        for (int i_c = 0; i_c < 4; ++i_c)
        {
                int l_v = l_bits - 32*i_c;
                if(l_v >= 32)
                {
                        l_mask.s6_addr32[i_c] = 0xffffffff;
                }
                else if(l_v <= 0)
                {
                        l_mask.s6_addr32[i_c] = 0;
                }
                else
                {
                        l_mask.s6_addr32[i_c] = htonl(~((1 << (32 - l_bits + 32*i_c)) - 1));
                }
        }
        // -------------------------------------------------
        // get truncated string
        // -------------------------------------------------
        char l_nm_ip[64];
        if ((size_t)(l_slash_pos - a_buf) >= (sizeof(l_nm_ip)-1))
        {
                // netmask too long
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        strncpy(l_nm_ip, a_buf, l_slash_pos - a_buf);
        l_nm_ip[l_slash_pos - a_buf] = '\0';
        // -------------------------------------------------
        // convert to ipaddr
        // -------------------------------------------------
        struct in6_addr l_in6;
        int l_s;
        l_s = inet_pton(AF_INET6, l_nm_ip, &l_in6);
        if(l_s != 1)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create masked address
        // -------------------------------------------------
        struct in6_addr l_masked_addr;
        for (int i_c = 0; i_c < 4; ++i_c)
        {
                l_masked_addr.s6_addr32[i_c] = l_in6.s6_addr32[i_c] & l_mask.s6_addr32[i_c];
        }
        if(!ipv6_arr)
        {
                ipv6_arr = new ipv6_set_t[129];
        }
        // ----------------------------------------
        // iterate through to handle redundancies
        // ----------------------------------------
        for(int i = 0 ;i<129;++i) {
                // ----------------------------------------
                // Check if prefix of prefix is already in 
                // nms (create new with l_masked_addr[i] & temp_mask[i])
                // ----------------------------------------
                if(i<l_bits) {
                        in6_addr input_masked;
                        for (int i_c = 0; i_c < 4; ++i_c)
                        {
                                int l_v = i - 32*i_c;
                                if(l_v >= 32)
                                {
                                        input_masked.s6_addr32[i_c] = l_in6.s6_addr32[i_c] & 0xffffffff;
                                }
                                else if(l_v <= 0)
                                {
                                        input_masked.s6_addr32[i_c] = 0;
                                }
                                else
                                {
                                        input_masked.s6_addr32[i_c] = l_in6.s6_addr32[i_c] & htonl(~((1 << (32 - i + 32*i_c)) - 1));
                                }
                        }
                        if(ipv6_arr[i].find(input_masked)!=ipv6_arr[i].end()) {
                                break;
                        }
                }
                // ----------------------------------------
                // check to find all CIDRs and IPs matching
                // this prefix and delete
                // ----------------------------------------
                else if(i>l_bits) {
                        std::set<in6_addr>::iterator itr = ipv6_arr[i].lower_bound(l_masked_addr);
                        while(itr!=ipv6_arr[i].end()) {
                                if((itr->s6_addr32[0] & l_mask.s6_addr32[0])==l_masked_addr.s6_addr32[0] &&
                                        (itr->s6_addr32[1] & l_mask.s6_addr32[1])==l_masked_addr.s6_addr32[1] &&
                                        (itr->s6_addr32[2] & l_mask.s6_addr32[2])==l_masked_addr.s6_addr32[2] &&
                                        (itr->s6_addr32[3] & l_mask.s6_addr32[3])==l_masked_addr.s6_addr32[3]) {
                                        itr = ipv6_arr[i].erase(itr);
                                continue;
                                }
                                break;
                        }
                }
        }
        // -------------------------------------------------
        // add
        // -------------------------------------------------
        ipv6_arr[l_bits].insert(l_masked_addr);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t nms::add_ipv6(const char *a_buf, uint32_t a_buf_len)
{
        if(memchr(a_buf, '/', a_buf_len) == NULL)
        {
                return add_ipv6_plain(a_buf, a_buf_len);
        }
        return add_ipv6_cidr(a_buf, a_buf_len);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t nms::contains_ipv4(bool &ao_match, const char *a_buf, uint32_t a_buf_len)
{
        ao_match = false;
        // convert to ipv4
        in_addr l_in;
        int l_s;
        l_s = inet_pton(AF_INET, a_buf, &l_in);
        if(l_s != 1)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        for(int l_bits=0; l_bits<=32; ++l_bits)
        {
                // -------------------------------------------------
                // Construct prefix mask
                // -------------------------------------------------
                const uint32_t l_nm = (l_bits == 0) ? 0 : htonl(~((1 << (32 - l_bits)) - 1));
                // -------------------------------------------------
                // If prefix found, ip is contained
                // -------------------------------------------------
                if( ipv4_arr[l_bits].find(l_nm & l_in.s_addr) != ipv4_arr[l_bits].end())
                {
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t nms::contains_ipv6(bool &ao_match, const char *a_buf, uint32_t a_buf_len)
{
        ao_match = false;
        if(!ipv4_arr)
        {
                // error???
                return WAFLZ_STATUS_OK;
        }
        in6_addr l_in6;
        int l_s;
        l_s = inet_pton(AF_INET6, a_buf, &l_in6);
        if(l_s != 1)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        for(int l_bits=0; l_bits<129; ++l_bits)
        {
                // -------------------------------------------------
                // Construct prefix
                // -------------------------------------------------
                in6_addr l_masked;
                for (int i_c = 0; i_c < 4; ++i_c)
                {
                        int32_t l_pos = l_bits - 32*i_c;
                        if(l_pos >= 32)
                        {
                                l_masked.s6_addr32[i_c] = l_in6.s6_addr32[i_c] & 0xffffffff;
                        }
                        else if(l_pos <= 0)
                        {
                                l_masked.s6_addr32[i_c] = 0;
                        }
                        else
                        {
                                l_masked.s6_addr32[i_c] = l_in6.s6_addr32[i_c] & htonl(~((1 << (32 - l_bits + 32*i_c)) - 1));
                        }
                }
                // -------------------------------------------------
                // If prefix found, IP is contained
                // -------------------------------------------------
                if(ipv6_arr[l_bits].find(l_masked) != ipv6_arr[l_bits].end())
                {
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: Pairwise check for prefixes, say length i, that match up to the last bit, then compress them
//              to length (i-1) prefix
//: \return:  Status code
//: \param:   None
//: ----------------------------------------------------------------------------
int32_t nms::compress() {
        // -------------------------------------------------
        // Iterate through IPv4 prefixes
        // -------------------------------------------------
        for(int l_bits = 32;l_bits>0;--l_bits) {
                std::set<in_addr_t>::iterator itr = ipv4_arr[l_bits].begin();
                if(itr==ipv4_arr[l_bits].end()) {
                        continue;
                }
                // -------------------------------------------------
                // Construct length (i-1) mask
                // -------------------------------------------------
                uint32_t next_mask = (l_bits-1 == 0) ? 0 : htonl(~((1 << (32 - (l_bits-1))) - 1));
                while(itr!=ipv4_arr[l_bits].end()) {
                        std::set<in_addr_t>::iterator next_itr=itr;
                        next_itr++;
                        if(next_itr==ipv4_arr[l_bits].end()) {
                                break;
                        }
                        // -------------------------------------------------
                        // Check if contiguous prefixes match after applying
                        // (i-1) mask
                        // -------------------------------------------------
                        if((*next_itr & next_mask)==(*itr & next_mask) ) {
                                ipv4_arr[l_bits-1].insert(*itr & next_mask);
                                ipv4_arr[l_bits].erase(itr);
                                itr = ipv4_arr[l_bits].erase(next_itr);
                                continue;
                        }
                        itr=next_itr;
                }
        }
        // -------------------------------------------------
        // Iterate through IPv6 prefixes
        // -------------------------------------------------
        for(int l_bits = 128;l_bits>0;--l_bits) {
                std::set<in6_addr>::iterator itr = ipv6_arr[l_bits].begin();
                // -------------------------------------------------
                // If empty, go to next prefix length
                // -------------------------------------------------
                if(itr==ipv6_arr[l_bits].end()) {
                        continue;
                }
                // -------------------------------------------------
                // Construct length (i-1) mask
                // -------------------------------------------------
                in6_addr l_next_mask;
                for (int i_c = 0; i_c < 4; ++i_c)
                {
                        int l_v = (l_bits-1) - 32*i_c;
                        if(l_v >= 32)
                        {
                                l_next_mask.s6_addr32[i_c] = 0xffffffff;
                        }
                        else if(l_v <= 0)
                        {
                                l_next_mask.s6_addr32[i_c] = 0;
                        }
                        else
                        {
                                l_next_mask.s6_addr32[i_c] = htonl(~((1 << (32 - (l_bits-1) + 32*i_c)) - 1));
                        }
                }
                while(itr!=ipv6_arr[l_bits].end()) {
                        std::set<in6_addr>::iterator next_itr=itr;
                        next_itr++;
                        // -------------------------------------------------
                        // Check if contiguous IDs match after applying 
                        // (i-1) mask
                        // -------------------------------------------------
                        if( (next_itr->s6_addr32[0] & l_next_mask.s6_addr32[0] ) == (itr->s6_addr32[0] & l_next_mask.s6_addr32[0])
                                && (next_itr->s6_addr32[1] & l_next_mask.s6_addr32[1] ) == (itr->s6_addr32[1] & l_next_mask.s6_addr32[1])
                                && (next_itr->s6_addr32[2] & l_next_mask.s6_addr32[2] ) == (itr->s6_addr32[2] & l_next_mask.s6_addr32[2])
                                && (next_itr->s6_addr32[3] & l_next_mask.s6_addr32[3] ) == (itr->s6_addr32[3] & l_next_mask.s6_addr32[3]) )  {
                                // -------------------------------------------------
                                // Construct (i-1) prefix, and add, erasing
                                // previous prefixes
                                // -------------------------------------------------
                                in6_addr next_prefix;
                                for(int i_c = 0;i_c<4;++i_c) {
                                        next_prefix.s6_addr32[i_c]=itr->s6_addr32[i_c] & l_next_mask.s6_addr32[i_c];
                                }
                                ipv6_arr[l_bits-1].insert(next_prefix);
                                ipv6_arr[l_bits].erase(itr);
                                itr = ipv6_arr[l_bits].erase(next_itr);
                                continue;
                        }
                        itr = next_itr;
                }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: ****************************************************************************
//:                            U T I L I T I E S
//: ****************************************************************************
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define MAX_READLINE_SIZE 4096
#define IP_STR_SEPARATOR ','
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t create_nms_from_str(nms **ao_nms, const std::string &a_str)
{
        //NDBG_PRINT("%sNMS_FROM_STR%s: %s\n",ANSI_COLOR_BG_WHITE, ANSI_COLOR_OFF, a_str.c_str());
        if(!ao_nms)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_nms = NULL;
        // -------------------------------------------------
        // split by IP string sep...
        // -------------------------------------------------
        int32_t l_s;
        nms *l_nms = new nms();
        size_t l_start = 0;
        size_t l_end = 0;
        while((l_end = a_str.find(IP_STR_SEPARATOR, l_start)) != std::string::npos)
        {
                if(l_end != l_start)
                {
                        std::string i_str = a_str.substr(l_start, l_end - l_start);
                        i_str.erase( std::remove_if( i_str.begin(), i_str.end(), ::isspace ), i_str.end() );
                        l_s = l_nms->add(i_str.c_str(), i_str.length());
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                if(l_nms) { delete l_nms; l_nms = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                l_start = l_end + 1;
        }
        if(l_end != l_start)
        {
                std::string i_str = a_str.substr(l_start);
                i_str.erase( std::remove_if( i_str.begin(), i_str.end(), ::isspace ), i_str.end() );
                l_s = l_nms->add(i_str.c_str(), i_str.length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_nms) { delete l_nms; l_nms = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
        }
        *ao_nms = l_nms;
        l_nms->compress();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t create_nms_from_file(nms **ao_nms, const std::string &a_file)
{
        if(!ao_nms)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_nms = NULL;
        //NDBG_PRINT("%sNMS_FROM_FILE%s: %s\n",ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF, a_file.c_str());
        FILE * l_fp;
        l_fp = fopen(a_file.c_str(),"r");
        if (l_fp == NULL)
        {
                //NDBG_PRINT("error opening file: %s.  Reason: %s\n", a_file.c_str(), strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        nms *l_nms = new nms();
        char l_rline[MAX_READLINE_SIZE];
        while(fgets(l_rline, sizeof(l_rline), l_fp))
        {
                size_t l_rline_len = strnlen(l_rline, MAX_READLINE_SIZE);
                if(!l_rline_len)
                {
                        continue;
                }
                else if(l_rline_len == MAX_READLINE_SIZE)
                {
                        // line was truncated
                        //TRC_OUTPUT("Error: lines must be shorter than %d chars\n", MAX_READLINE_SIZE);
                        if(l_nms) { delete l_nms; l_nms = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // TODO -zero copy version???
                // -----------------------------------------
                // nuke endline
                l_rline[l_rline_len - 1] = '\0';
                std::string l_line(l_rline);
                l_line.erase( std::remove_if( l_line.begin(), l_line.end(), ::isspace ), l_line.end() );
                if(l_line.empty())
                {
                        continue;
                }
                int32_t l_s;
                l_s = l_nms->add(l_line.c_str(), l_line.length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_nms) { delete l_nms; l_nms = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                //NDBG_PRINT("READLINE: %s\n", l_line.c_str());
        }
        *ao_nms = l_nms;
        l_nms->compress();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t create_nms_from_ip_str_list(nms **ao_nms,
                                    const ip_str_list_t &a_ip_str_list)
{
        if(!ao_nms)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_nms = NULL;
        nms *l_nms = new nms();
        for(ip_str_list_t::const_iterator i_ip = a_ip_str_list.begin();
            i_ip != a_ip_str_list.end();
            ++i_ip)
        {
                if(!*i_ip)
                {
                        continue;
                }
                const std::string &l_ip = **i_ip;
                if(l_ip.empty())
                {
                        continue;
                }
                int32_t l_s;
                l_s = l_nms->add(l_ip.c_str(), l_ip.length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_nms) { delete l_nms; l_nms = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
        }
        *ao_nms = l_nms;
        l_nms->compress();
        return WAFLZ_STATUS_OK;
}
}
