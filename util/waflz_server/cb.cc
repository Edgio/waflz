//: ----------------------------------------------------------------------------
//: Copyright (C) 2019 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    cb.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    09/30/2019
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
#include "cb.h"
#include "is2/srvr/rqst.h"
#include "is2/srvr/session.h"
#include "is2/srvr/lsnr.h"
#include "is2/support/nbq.h"
#include "is2/support/data.h"
#include "support/ndebug.h"
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
namespace ns_waflz_server {
//: ----------------------------------------------------------------------------
//: extern...
//: ----------------------------------------------------------------------------
bool g_random_ips = false;
__thread char g_clnt_addr_str[INET6_ADDRSTRLEN];
__thread char g_rqst_line[4096];
//: ----------------------------------------------------------------------------
//: get ip callback
//: ----------------------------------------------------------------------------
int32_t get_rqst_ip_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        // -------------------------------------------------
        // random ips
        // -------------------------------------------------
        if(g_random_ips)
        {
                uint32_t l_addr;
                // -----------------------------------------
                //   16843009 == 1.1.1.1
                // 4294967295 == 255.255.255.255
                // -----------------------------------------
                l_addr = ((uint32_t)rand()) % (4294967295 + 1 - 16843009) + 16843009;
                snprintf(g_clnt_addr_str, INET6_ADDRSTRLEN, "%d.%d.%d.%d",
                         ((l_addr & 0xFF000000) >> 24),
                         ((l_addr & 0x00FF0000) >> 16),
                         ((l_addr & 0x0000FF00) >> 8),
                         ((l_addr & 0x000000FF)));
                //NDBG_PRINT("addr: %s\n", s_clnt_addr_str);
                *a_data = g_clnt_addr_str;
                *a_len = strnlen(g_clnt_addr_str, INET6_ADDRSTRLEN);
                return 0;
        }
        // -------------------------------------------------
        // request object
        // -------------------------------------------------
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        // -------------------------------------------------
        // check for header override
        // -------------------------------------------------
#define _HEADER_SRC_IP "x-waflz-ip"
        const ns_is2::mutable_data_map_list_t& l_headers(l_ctx->m_rqst->get_header_map());
        ns_is2::mutable_data_t i_hdr;
        if(ns_is2::find_first(i_hdr, l_headers, _HEADER_SRC_IP, sizeof(_HEADER_SRC_IP)))
        {
                *a_data = i_hdr.m_data;
                *a_len = i_hdr.m_len;
                return 0;
        }
        // -------------------------------------------------
        // get ip from request
        // -------------------------------------------------
        ns_is2::host_info l_host_info = l_ctx->get_host_info();
        g_clnt_addr_str[0] = '\0';
        if(l_host_info.m_sa_len == sizeof(sockaddr_in))
        {
                // a thousand apologies for this monstrosity :(
                errno = 0;
                const char *l_s;
                l_s = inet_ntop(AF_INET,
                                &(((sockaddr_in *)(&(l_host_info.m_sa)))->sin_addr),
                                g_clnt_addr_str,
                                INET_ADDRSTRLEN);
                if(!l_s)
                {
                        NDBG_PRINT("Error performing inet_ntop. Reason: %s\n", strerror(errno));
                        return -1;
                }
        }
        else if(l_host_info.m_sa_len == sizeof(sockaddr_in6))
        {
                // a thousand apologies for this monstrosity :(
                errno = 0;
                const char *l_s;
                l_s = inet_ntop(AF_INET6,
                                &(((sockaddr_in6 *)(&(l_host_info.m_sa)))->sin6_addr),
                                g_clnt_addr_str,
                                INET6_ADDRSTRLEN);
                if(!l_s)
                {
                        NDBG_PRINT("Error performing inet_ntop. Reason: %s\n", strerror(errno));
                        return -1;
                }
        }
        if(strnlen(g_clnt_addr_str, INET6_ADDRSTRLEN) <= 4)
        {
                snprintf(g_clnt_addr_str, INET6_ADDRSTRLEN, "127.0.0.1");
                return -1;
        }
        *a_data = g_clnt_addr_str;
        *a_len = strnlen(g_clnt_addr_str, INET6_ADDRSTRLEN);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get rqst line callback
//: ----------------------------------------------------------------------------
int32_t get_rqst_line_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        snprintf(g_rqst_line, 4096, "%s %.*s HTTP/%d.%d",
                 l_rqst->get_method_str(),
                 l_rqst->get_url().m_len, l_rqst->get_url().m_data,
                 l_rqst->m_http_major,
                 l_rqst->m_http_minor);
        *a_data = g_rqst_line;
        *a_len = strnlen(g_rqst_line, 4096);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get rqst method callback
//: ----------------------------------------------------------------------------
int32_t get_rqst_method_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_method_str();
        *a_len = strlen(l_rqst->get_method_str());
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_protocol_cb
//: ----------------------------------------------------------------------------
int32_t get_rqst_protocol_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        char s_protocol[32];
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        snprintf(s_protocol, 32, "HTTP/%d.%d",
                 l_rqst->m_http_major,
                 l_rqst->m_http_minor);
        *a_data = s_protocol;
        *a_len = strlen(s_protocol);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_scheme_cb
//: ----------------------------------------------------------------------------
int32_t get_rqst_scheme_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        char s_scheme[32];
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::scheme_t l_scheme = l_ctx->get_scheme();
        if(l_scheme == ns_is2::SCHEME_TCP)
        {
                snprintf(s_scheme,32,"http");
        }
        else if(l_scheme == ns_is2::SCHEME_TLS)
        {
                snprintf(s_scheme,32,"https");
        }
        *a_data = s_scheme;
        *a_len = strlen(s_scheme);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_port_cb
//: ----------------------------------------------------------------------------
int32_t get_rqst_port_cb(uint32_t *a_val, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        *a_val = l_ctx->m_lsnr->get_port();
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_port_cb
//: ----------------------------------------------------------------------------
int32_t get_rqst_host_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        const ns_is2::mutable_data_map_list_t& l_hm = l_rqst->get_header_map();
        const ns_is2::mutable_data_map_list_t& l_headers(l_ctx->m_rqst->get_header_map());
        ns_is2::mutable_data_t i_hdr;
        if(ns_is2::find_first(i_hdr, l_headers, "Host", sizeof("Host")))
        {
                *a_data = i_hdr.m_data;
                *a_len = i_hdr.m_len;
                return 0;
        }
        *a_data = "localhost";
        *a_len = strlen("localhost");
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_url_cb
//: ----------------------------------------------------------------------------
int32_t get_rqst_url_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_url().m_data;
        *a_len = l_rqst->get_url().m_len;
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_uri_cb
//: ----------------------------------------------------------------------------
int32_t get_rqst_uri_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_url().m_data;
        *a_len = l_rqst->get_url().m_len;
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_uri_cb
//: ----------------------------------------------------------------------------
int32_t get_rqst_path_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_url_path().m_data;
        *a_len = l_rqst->get_url_path().m_len;
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_query_str_cb
//: ----------------------------------------------------------------------------
int32_t get_rqst_query_str_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_url_query().m_data;
        *a_len = l_rqst->get_url_query().m_len;
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_id_cb
//: ----------------------------------------------------------------------------
#define _UUID_STR  "aabbccddeeff"
int32_t get_rqst_id_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        *a_data = _UUID_STR;
        *a_len = strlen(_UUID_STR);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_header_size_cb
//: ----------------------------------------------------------------------------
int32_t get_rqst_header_size_cb(uint32_t *a_val, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_val = l_rqst->get_header_list().size();
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_header_w_idx_cb
//: ----------------------------------------------------------------------------
int32_t get_rqst_header_w_idx_cb(const char **ao_key,
                                        uint32_t *ao_key_len,
                                        const char **ao_val,
                                        uint32_t *ao_val_len,
                                        void *a_ctx,
                                        uint32_t a_idx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *ao_key = NULL;
        *ao_key_len = 0;
        *ao_val = NULL;
        *ao_val_len = 0;
        const ns_is2::mutable_arg_list_t &l_h_list = l_rqst->get_header_list();
        ns_is2::mutable_arg_list_t::const_iterator i_h = l_h_list.begin();
        std::advance(i_h, a_idx);
        if(i_h == l_h_list.end())
        {
                return -1;
        }
        *ao_key = i_h->m_key;
        *ao_key_len = i_h->m_key_len;
        *ao_val = i_h->m_val;
        *ao_val_len = i_h->m_val_len;
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_body_str_cb
//: ----------------------------------------------------------------------------
int32_t get_rqst_body_str_cb(char *ao_data,
                             uint32_t *ao_data_len,
                             bool ao_is_eos,
                             void *a_ctx,
                             uint32_t *a_to_read)
{
        //NDBG_PRINT(": ======================== \n");
        //NDBG_PRINT(": ao_data:     %p\n", ao_data);
        //NDBG_PRINT(": ao_data_len: %u\n", ao_data_len);
        //NDBG_PRINT(": ao_is_eos:   %d\n", ao_is_eos);
        //NDBG_PRINT(": a_ctx:       %p\n", a_ctx);
        //NDBG_PRINT(": a_to_read:   %u\n", a_to_read);
        if (NULL == a_ctx)
        {
                ao_is_eos = true;
                *ao_data_len = 0;
                return 0;
        }
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                ao_is_eos = true;
                *ao_data_len = 0;
                return 0;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                ao_is_eos = true;
                *ao_data_len = 0;
                return 0;
        }
        ns_is2::nbq *l_q = l_rqst->get_body_q();
        if(!l_q)
        {
                ao_is_eos = true;
                *ao_data_len = 0;
                return 0;
        }
        // -------------------------------------------------
        // set not done
        // -------------------------------------------------
        ao_is_eos = false;
        *ao_data_len = 0;
        // -------------------------------------------------
        // cal how much to read
        // -------------------------------------------------
        uint32_t l_left = *a_to_read;
        if(*a_to_read > l_q->read_avail())
        {
                l_left = l_q->read_avail();
        }
        // -------------------------------------------------
        // read until not avail or ao_data_len
        // -------------------------------------------------
        char *l_cur_ptr = ao_data;
        while(l_left)
        {
                int64_t l_read = 0;
                l_read = l_q->read(l_cur_ptr, l_left);
                if(l_read < 0)
                {
                        // TODO error
                        ao_is_eos = true;
                        ao_data_len = 0;
                        return 0;
                }
                l_cur_ptr += (uint32_t)l_read;
                *ao_data_len += (uint32_t)l_read;
                l_left -= (uint32_t)l_read;
        }
        if(!l_q->read_avail())
        {
                ao_is_eos = true;
        }
        //ns_is2::mem_display((const uint8_t *)ao_data, ao_data_len);
        //NDBG_PRINT(": ************************ \n");
        //NDBG_PRINT(": ao_data:     %p\n", ao_data);
        //NDBG_PRINT(": ao_data_len: %u\n", ao_data_len);
        //NDBG_PRINT(": ao_is_eos:   %d\n", ao_is_eos);
        //NDBG_PRINT(": a_ctx:       %p\n", a_ctx);
        //NDBG_PRINT(": a_to_read:   %u\n", a_to_read);
        return 0;
}
}
