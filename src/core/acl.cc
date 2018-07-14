//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    acl.cc
//: \details: TODO
//: \author:  Devender Singh
//: \date:    07/14/2017
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
#include "support/ndebug.h"
#include "support/trace_internal.h"
#include "op/regex.h"
#include "support/geoip2_mmdb.h"
#include "support/string_util.h"
#include "op/nms.h"
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "waflz/acl.h"
#include "config.pb.h"
#include "event.pb.h"
#include "acl.pb.h"
#include <errno.h>
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define GET_RQST_DATA(_cb) do { \
        l_buf = NULL; \
        l_buf_len = 0; \
        if(_cb) { \
                l_s = _cb(&l_buf, l_buf_len, a_ctx); \
                if(l_s != 0) { \
                        WAFLZ_PERROR(m_err_msg, "performing %s", #_cb); \
                        return WAFLZ_STATUS_ERROR; \
                } \
        } \
} while(0)


namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: \details ctor
//: \return  None
//: \param   None
//: ----------------------------------------------------------------------------
acl::acl(geoip2_mmdb &a_geoip2_mmdb):
        m_err_msg(),
        m_pb(NULL),
        m_geoip2_mmdb(a_geoip2_mmdb),
        m_ip_whitelist(NULL),
        m_ip_blacklist(NULL),
        m_country_whitelist(),
        m_country_blacklist(),
        m_asn_whitelist(),
        m_asn_blacklist(),
        m_url_rx_whitelist(NULL),
        m_url_rx_blacklist(NULL),
        m_ua_rx_whitelist(NULL),
        m_ua_rx_blacklist(NULL),
        m_referer_rx_whitelist(NULL),
        m_referer_rx_blacklist(NULL),
        m_cookie_rx_whitelist(NULL),
        m_cookie_rx_blacklist(NULL)
{
        m_pb = new waflz_pb::acl();
}
//: ----------------------------------------------------------------------------
//: \brief   dtor
//: \deatils
//: \return  None
//: ----------------------------------------------------------------------------
acl::~acl(void)
{
#define _DELETE_OBJ(_obj) if(_obj) { delete _obj; _obj = NULL; }

        _DELETE_OBJ(m_ip_whitelist);
        _DELETE_OBJ(m_ip_blacklist);
        _DELETE_OBJ(m_url_rx_whitelist);
        _DELETE_OBJ(m_url_rx_blacklist);
        _DELETE_OBJ(m_ua_rx_whitelist);
        _DELETE_OBJ(m_ua_rx_blacklist);
        _DELETE_OBJ(m_referer_rx_whitelist);
        _DELETE_OBJ(m_referer_rx_blacklist);
        _DELETE_OBJ(m_cookie_rx_whitelist);
        _DELETE_OBJ(m_cookie_rx_blacklist);
        if(m_pb) { delete m_pb; m_pb = NULL; }
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int32_t compile_regex_list(regex **ao_regex,
                                  const ::google::protobuf::RepeatedPtrField< ::std::string>& a_list,
                                  uint32_t a_list_len)
{
        if(!ao_regex)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_regex = NULL;
        if(!a_list_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // create regex string
        std::string l_rx;
        l_rx = "(";
        typedef ::google::protobuf::RepeatedPtrField< ::std::string> gpb_list_t;
        uint32_t i_idx = 0;
        for(gpb_list_t::const_iterator i_s = a_list.begin();
            i_s != a_list.end();
            ++i_s, ++i_idx)
        {
                l_rx += *i_s;
                if((i_idx+1) < a_list_len)
                {
                        l_rx += "|";
                }
        }
        l_rx += ")";
        regex *l_pcre = new regex();
        int32_t l_s;
        l_s = l_pcre->init(l_rx.c_str(), l_rx.length());
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -more info
                //WAFLZ_PERROR(m_err_msg, "compiling url whitelist");
                if(l_pcre)
                {
                        delete l_pcre;
                        l_pcre = NULL;
                }
                return WAFLZ_STATUS_ERROR;
        }
        *ao_regex = l_pcre;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t acl::compile()
{
        // -------------------------------------------------
        // acl: ip
        // -------------------------------------------------
        // "ip":
        // {
        //     "whitelist": ["192.168.1.1", "192.168.2.1"],
        //     "blacklist": ["8.8.8.8"]
        // },
        // -------------------------------------------------
        if(m_pb->has_ip())
        {
                if(m_pb->ip().whitelist_size())
                {
                        if(m_ip_whitelist)
                        {
                                delete m_ip_whitelist;
                                m_ip_whitelist = NULL;
                        }
                        m_ip_whitelist = new nms();
                        for(int32_t i_ip = 0; i_ip < m_pb->ip().whitelist_size(); ++i_ip)
                        {
                                const std::string &l_str = m_pb->ip().whitelist(i_ip);
                                m_ip_whitelist->add(l_str.c_str(), l_str.length());
                        }
                }
                if(m_pb->ip().blacklist_size())
                {
                        if(m_ip_blacklist)
                        {
                                delete m_ip_blacklist;
                                m_ip_blacklist = NULL;
                        }
                        m_ip_blacklist = new nms();
                        for(int32_t i_ip = 0; i_ip < m_pb->ip().blacklist_size(); ++i_ip)
                        {
                                const std::string &l_str = m_pb->ip().blacklist(i_ip);
                                m_ip_blacklist->add(l_str.c_str(), l_str.length());
                        }
                }
        }
        // -------------------------------------------------
        // country
        // -------------------------------------------------
        //         "country":
        //         {
        //             "whitelist": ["US","CA"],
        //             "blacklist": ["RU", "CN"]
        //         },
        // -------------------------------------------------
        if(m_pb->has_country())
        {
                for(int32_t i_ip = 0; i_ip < m_pb->country().whitelist_size(); ++i_ip)
                {
                        m_country_whitelist.insert(m_pb->country().whitelist(i_ip));
                }
                for(int32_t i_ip = 0; i_ip < m_pb->country().blacklist_size(); ++i_ip)
                {
                        m_country_blacklist.insert(m_pb->country().blacklist(i_ip));
                }
        }
        // -------------------------------------------------
        // ASN
        // -------------------------------------------------
        if(m_pb->has_asn())
        {
                for(int32_t i_ip = 0; i_ip < m_pb->asn().whitelist_size(); ++i_ip)
                {
                        m_asn_whitelist.insert(m_pb->asn().whitelist(i_ip));
                }
                for(int32_t i_ip = 0; i_ip < m_pb->asn().blacklist_size(); ++i_ip)
                {
                        m_asn_blacklist.insert(m_pb->asn().blacklist(i_ip));
                }
        }
        // -------------------------------------------------
        // url
        // -------------------------------------------------
        if(m_pb->has_url())
        {
                if(m_pb->url().whitelist_size())
                {
                        int32_t l_s;
                        l_s = compile_regex_list(&m_url_rx_whitelist,
                                                 m_pb->url().whitelist(),
                                                 m_pb->url().whitelist_size());
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "compiling url whitelist");
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                if(m_pb->url().blacklist_size())
                {
                        int32_t l_s;
                        l_s = compile_regex_list(&m_url_rx_blacklist,
                                                 m_pb->url().blacklist(),
                                                 m_pb->url().blacklist_size());
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "compiling url blacklist");
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        // -------------------------------------------------
        // user-agent
        // -------------------------------------------------
        if(m_pb->has_user_agent())
        {
                if(m_pb->user_agent().whitelist_size())
                {
                        int32_t l_s;
                        l_s = compile_regex_list(&m_ua_rx_whitelist,
                                                 m_pb->user_agent().whitelist(),
                                                 m_pb->user_agent().whitelist_size());
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "compiling user-agent whitelist");
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                if(m_pb->user_agent().blacklist_size())
                {
                        int32_t l_s;
                        l_s = compile_regex_list(&m_ua_rx_blacklist,
                                                 m_pb->user_agent().blacklist(),
                                                 m_pb->user_agent().blacklist_size());
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "compiling user-agent blacklist");
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        // -------------------------------------------------
        // referer
        // -------------------------------------------------
        if(m_pb->has_referer())
        {
                if(m_pb->referer().whitelist_size())
                {
                        int32_t l_s;
                        l_s = compile_regex_list(&m_referer_rx_whitelist,
                                                 m_pb->referer().whitelist(),
                                                 m_pb->referer().whitelist_size());
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "compiling referer whitelist");
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                if(m_pb->referer().blacklist_size())
                {
                        int32_t l_s;
                        l_s = compile_regex_list(&m_referer_rx_blacklist,
                                                 m_pb->referer().blacklist(),
                                                 m_pb->referer().blacklist_size());
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "compiling referer blacklist");
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        // -------------------------------------------------
        // cookie
        // -------------------------------------------------
        if(m_pb->has_cookie())
        {
                if(m_pb->cookie().whitelist_size())
                {
                        int32_t l_s;
                        l_s = compile_regex_list(&m_cookie_rx_whitelist,
                                                 m_pb->cookie().whitelist(),
                                                 m_pb->cookie().whitelist_size());
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "compiling cookie whitelist");
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                if(m_pb->cookie().blacklist_size())
                {
                        int32_t l_s;
                        l_s = compile_regex_list(&m_cookie_rx_blacklist,
                                                 m_pb->cookie().blacklist(),
                                                 m_pb->cookie().blacklist_size());
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "compiling cookie blacklist");
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        // -------------------------------------------------
        // allowed_http_methods
        // -------------------------------------------------
        if(m_pb->allowed_http_methods_size())
        {
                for(int32_t i_t = 0; i_t < m_pb->allowed_http_methods_size(); ++i_t)
                {
                        m_allowed_http_methods.insert(m_pb->allowed_http_methods(i_t));
                }
        }
        // -------------------------------------------------
        // allowed_http_versions
        // -------------------------------------------------
        if(m_pb->allowed_http_versions_size())
        {
                for(int32_t i_t = 0; i_t < m_pb->allowed_http_versions_size(); ++i_t)
                {
                        m_allowed_http_versions.insert(m_pb->allowed_http_versions(i_t));
                }
        }
        // -------------------------------------------------
        // allowed_request_content
        // -------------------------------------------------
        if(m_pb->allowed_request_content_types_size())
        {
                for(int32_t i_t = 0; i_t < m_pb->allowed_request_content_types_size(); ++i_t)
                {
                        m_allowed_request_content_types.insert(m_pb->allowed_request_content_types(i_t));
                }
        }
        // -------------------------------------------------
        // allowed_request_content
        // -------------------------------------------------
        if(m_pb->disallowed_extensions_size())
        {
                for(int32_t i_t = 0; i_t < m_pb->disallowed_extensions_size(); ++i_t)
                {
                        m_disallowed_extensions.insert(m_pb->disallowed_extensions(i_t));
                }
        }
        // -------------------------------------------------
        // disallowed_headers
        // -------------------------------------------------
        if(m_pb->disallowed_headers_size())
        {
                for(int32_t i_t = 0; i_t < m_pb->disallowed_headers_size(); ++i_t)
                {
                        m_disallowed_headers.insert(m_pb->disallowed_headers(i_t));
                }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t acl::process_whitelist(bool &ao_match, void *a_ctx)
{
        ao_match = false;
        const char *l_key = NULL;
        const char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        int32_t l_s;
        // -------------------------------------------------
        // ip
        // -------------------------------------------------
        GET_RQST_DATA(rqst_ctx::s_get_rqst_src_addr_cb);
        if(m_ip_whitelist &&
           l_buf &&
           l_buf_len)
        {
                l_s = m_ip_whitelist->contains(ao_match, l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log error reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // if in whitelist -bail out of modsec processing
                if(ao_match)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // country
        // -------------------------------------------------
        if(m_country_whitelist.size() &&
           l_buf &&
           l_buf_len)
        {
                const char *l_cn = NULL;
                uint32_t l_cn_len = 0;
                l_s = m_geoip2_mmdb.get_country(&l_cn, l_cn_len, l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,
                                     "geoip2 country lookup: reason: %s",
                                     m_geoip2_mmdb.get_err_msg());
                        //return WAFLZ_STATUS_ERROR;
                        goto asn_check;
                }
                if(l_cn && l_cn_len)
                {
                        std::string l_cn_str;
                        l_cn_str.assign(l_cn, l_cn_len);
                        if(m_country_whitelist.find(l_cn_str) != m_country_whitelist.end())
                        {
                                ao_match = true;
                                return WAFLZ_STATUS_OK;
                        }
                }
        }
asn_check:
        // -------------------------------------------------
        // ASN
        // -------------------------------------------------
        if(m_asn_whitelist.size() &&
           l_buf &&
           l_buf_len)
        {
                uint32_t l_asn;
                l_s = m_geoip2_mmdb.get_asn(l_asn, l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,
                                     "geoip2 country lookup: reason: %s",
                                     m_geoip2_mmdb.get_err_msg());
                        //return WAFLZ_STATUS_ERROR;
                        goto url_check;
                }
                if(m_asn_whitelist.find(l_asn) != m_asn_whitelist.end())
                {
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
        }
url_check:
        // -------------------------------------------------
        // get url
        // -------------------------------------------------
        if(!m_url_rx_whitelist)
        {
                goto user_agent_check;
        }
        GET_RQST_DATA(rqst_ctx::s_get_rqst_uri_cb);
        if(m_url_rx_whitelist &&
           l_buf &&
           l_buf_len)
        {
                int32_t l_s;
                l_s = m_url_rx_whitelist->compare(l_buf, l_buf_len);
                // if failed to match
                if(l_s >= 0)
                {
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
        }
user_agent_check:
        // -------------------------------------------------
        // user-agent
        // -------------------------------------------------
        if(!m_ua_rx_whitelist ||
           !rqst_ctx::s_get_rqst_header_w_key_cb)
        {
                goto referer_check;
        }
        l_key = "User-Agent";
        l_s = rqst_ctx::s_get_rqst_header_w_key_cb(&l_buf,
                                                  l_buf_len,
                                                  a_ctx,
                                                  l_key,
                                                  strlen(l_key));
        if(l_s != 0)
        {
                WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_w_key_cb: key: %s", l_key);
        }
        if(m_ua_rx_whitelist &&
           l_buf &&
           l_buf_len)
        {
                int32_t l_s;
                l_s = m_ua_rx_whitelist->compare(l_buf, l_buf_len);
                // if failed to match
                if(l_s >= 0)
                {
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
        }
referer_check:
        // -------------------------------------------------
        // referer
        // -------------------------------------------------
        if(!m_referer_rx_whitelist ||
           !rqst_ctx::s_get_rqst_header_w_key_cb)
        {
                goto cookie_check;
        }
        l_key = "Referer";
        l_s = rqst_ctx::s_get_rqst_header_w_key_cb(&l_buf,
                                                  l_buf_len,
                                                  a_ctx,
                                                  l_key,
                                                  strlen(l_key));
        if(l_s != 0)
        {
                WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_w_key_cb: key: %s", l_key);
        }
        if(m_referer_rx_whitelist &&
           l_buf &&
           l_buf_len)
        {
                int32_t l_s;
                l_s = m_referer_rx_whitelist->compare(l_buf, l_buf_len);
                // if failed to match
                if(l_s >= 0)
                {
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
        }
cookie_check:
        // -------------------------------------------------
        // cookie
        // -------------------------------------------------
        if(!m_cookie_rx_whitelist ||
           !rqst_ctx::s_get_rqst_header_w_key_cb)
        {
                return WAFLZ_STATUS_OK;
        }
        l_key = "Cookie";
        l_s = rqst_ctx::s_get_rqst_header_w_key_cb(&l_buf,
                                                  l_buf_len,
                                                  a_ctx,
                                                  l_key,
                                                  strlen(l_key));
        if(l_s != 0)
        {
                WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_w_key_cb: key: %s", l_key);
        }
        if(m_cookie_rx_whitelist &&
           l_buf &&
           l_buf_len)
        {
                int32_t l_s;
                l_s =  m_cookie_rx_whitelist->compare(l_buf, l_buf_len);
                if(l_s >= 0)
                {
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t acl::process_blacklist(waflz_pb::event **ao_event, void *a_ctx)
{
        if(!ao_event)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_event = NULL;
        const char *l_key = NULL;
        const char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        int32_t l_s;
        waflz_pb::event *l_event = NULL;
        GET_RQST_DATA(rqst_ctx::s_get_rqst_src_addr_cb);
        // -------------------------------------------------
        // ip
        // -------------------------------------------------
        if(m_ip_blacklist &&
           l_buf &&
           l_buf_len)
        {
                bool l_match = false;
                l_s = m_ip_blacklist->contains(l_match, l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log error reason???
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_match)
                {
                        // alloc event...
                        l_event = new ::waflz_pb::event();
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        // ---------------------------------
                        // subevent
                        // ---------------------------------
                        l_sevent->set_rule_id(430108);
                        l_sevent->set_rule_msg("Blacklist IP match");
                        // top level rule msg
                        l_event->set_rule_msg("Blacklist IP match");
                        l_sevent->set_rule_op_name("ipMatch");
                        l_sevent->set_rule_op_param("ip_blacklist");
                        l_sevent->add_rule_tag("BLACKLIST/IP");
                        ::waflz_pb::event_var_t* l_rule_target = l_sevent->add_rule_target();
                        l_rule_target->set_name("TX");
                        l_rule_target->set_param("REAL_IP");
                        ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
                        l_var->set_name("TX:real_ip");
                        l_var->set_value(l_buf, l_buf_len);
                        *ao_event = l_event;
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // country
        // -------------------------------------------------
        if(m_country_blacklist.size() &&
           l_buf &&
           l_buf_len)
        {
                const char *l_cn = NULL;
                uint32_t l_cn_len = 0;
                l_s = m_geoip2_mmdb.get_country(&l_cn, l_cn_len, l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,
                                     "geoip2 country lookup: reason: %s",
                                     m_geoip2_mmdb.get_err_msg());
                        //return WAFLZ_STATUS_ERROR;
                        goto asn_check;
                }
                std::string l_cn_str;
                bool l_match = false;
                if(l_cn && l_cn_len)
                {
                        l_cn_str.assign(l_cn, l_cn_len);
                        if(m_country_blacklist.find(l_cn_str) != m_country_blacklist.end())
                        {
                                l_match = true;
                        }
                }
                if(l_match)
                {
                        // alloc event...
                        l_event = new ::waflz_pb::event();
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        // ---------------------------------
                        // subevent
                        // ---------------------------------
                        l_sevent->set_rule_id(430425);
                        l_sevent->set_rule_msg("Blacklist Country match");
                        // top level rule msg
                        l_event->set_rule_msg("Blacklist Country match");
                        l_sevent->set_rule_op_name("geoLookup");
                        l_sevent->set_rule_op_param("");
                        l_sevent->add_rule_tag("BLACKLIST/COUNTRY");
                        ::waflz_pb::event_var_t* l_rule_target = l_sevent->add_rule_target();
                        l_rule_target->set_name("TX");
                        l_rule_target->set_param("REAL_IP");
                        l_sevent->set_total_anomaly_score(5);
                        ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
                        l_var->set_name("GEO:COUNTRY_CODE");
                        l_var->set_value(l_cn_str);
                        *ao_event = l_event;
                        return WAFLZ_STATUS_OK;
                }
        }
asn_check:
        // -------------------------------------------------
        // ASN
        // -------------------------------------------------
        if(m_asn_blacklist.size() &&
           l_buf &&
           l_buf_len)
        {
                uint32_t l_asn;
                l_s = m_geoip2_mmdb.get_asn(l_asn, l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,
                                     "geoip2 country lookup: reason: %s",
                                     m_geoip2_mmdb.get_err_msg());
                        //return WAFLZ_STATUS_ERROR;
                        goto url_check;
                }
                bool l_match = false;
                if(m_asn_blacklist.find(l_asn) != m_asn_blacklist.end())
                {
                        l_match = true;
                }
                if(l_match)
                {
                        // alloc event...
                        l_event = new ::waflz_pb::event();
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        // ---------------------------------
                        // subevent
                        // ---------------------------------
                        l_sevent->set_rule_id(430001);
                        l_sevent->set_rule_msg("Blacklist ASN match");
                        // top level rule msg
                        l_event->set_rule_msg("Blacklist ASN match");
                        l_sevent->set_rule_op_name("asnLookup");
                        l_sevent->set_rule_op_param("");
                        l_sevent->add_rule_tag("BLACKLIST/ASN");
                        ::waflz_pb::event_var_t* l_rule_target = l_sevent->add_rule_target();
                        l_rule_target->set_name("TX");
                        l_rule_target->set_param("REAL_IP");
                        ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
                        l_var->set_name("GEO:ASN");
                        char l_asn_str[16];
                        snprintf(l_asn_str, 16, "AS%u", l_asn);
                        l_var->set_value(l_asn_str);
                        *ao_event = l_event;
                        return WAFLZ_STATUS_OK;
                }
        }
url_check:
        // -------------------------------------------------
        // url
        // -------------------------------------------------
        if(!m_url_rx_blacklist)
        {
                goto user_agent_check;
        }
        GET_RQST_DATA(rqst_ctx::s_get_rqst_uri_cb);
        if(m_url_rx_blacklist &&
           l_buf &&
           l_buf_len)
        {
                int32_t l_s;
                bool l_match = false;
                l_s = m_url_rx_blacklist->compare(l_buf, l_buf_len);
                if(l_s >= 0)
                {
                        l_match = true;
                }
                if(l_match)
                {
                        // alloc event...
                        l_event = new ::waflz_pb::event();
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        // ---------------------------------
                        // subevent
                        // ---------------------------------
                        l_sevent->set_rule_id(430002);
                        l_sevent->set_rule_msg("Blacklist URL match");
                        // Top level rule msg
                        l_event->set_rule_msg("Blacklist URL match");
                        l_sevent->set_rule_op_name("rx");
                        l_sevent->set_rule_op_param("");
                        l_sevent->add_rule_tag("BLACKLIST/URL");
                        l_sevent->set_total_anomaly_score(1);
                        l_sevent->set_total_sql_injection_score(0);
                        l_sevent->set_total_xss_score(0);
                        ::waflz_pb::event_var_t* l_rule_target = l_sevent->add_rule_target();
                        l_rule_target->set_name("REQUEST_URI_RAW");
                        ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
                        l_var->set_name("REQUEST_URI_RAW");
                        l_var->set_value(l_buf, l_buf_len);
                        *ao_event = l_event;
                        return WAFLZ_STATUS_OK;
                }
        }
user_agent_check:
        // -------------------------------------------------
        // user-agent
        // -------------------------------------------------
        if(!m_ua_rx_blacklist ||
           !rqst_ctx::s_get_rqst_header_w_key_cb)
        {
                goto referer_check;
        }
        l_key = "User-Agent";
        l_s = rqst_ctx::s_get_rqst_header_w_key_cb(&l_buf, l_buf_len, a_ctx, l_key, strlen(l_key));
        if(l_s != 0)
        {
                WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_w_key_cb: key: %s", l_key);
                goto referer_check;
        }
        if(m_ua_rx_blacklist &&
           l_buf &&
           l_buf_len)
        {
                int32_t l_s;
                bool l_match = false;
                std::string l_rx_capture;
                l_s = m_ua_rx_blacklist->compare(l_buf, l_buf_len, &l_rx_capture);
                if(l_s >= 0)
                {
                        l_match = true;
                }
                if(l_match)
                {
                        // alloc event...
                        l_event = new ::waflz_pb::event();
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        // ---------------------------------
                        // subevent
                        // ---------------------------------
                        l_sevent->set_rule_id(430614);
                        l_sevent->set_rule_msg("Blacklist User-Agent match");
                        // top level rule msg
                        l_event->set_rule_msg("Blacklist User-Agent match");
                        l_sevent->set_rule_op_name("rx");
                        l_sevent->set_rule_op_param(m_ua_rx_blacklist->get_regex_string());
                        l_sevent->add_rule_tag("BLACKLIST/USER-AGENT");
                        l_sevent->set_total_anomaly_score(2);
                        l_sevent->set_total_sql_injection_score(0);
                        l_sevent->set_total_xss_score(0);
                        ::waflz_pb::event_var_t* l_rule_target = l_sevent->add_rule_target();
                        l_rule_target->set_name("REQUEST_HEADERS");
                        l_rule_target->set_param("User-Agent");
                        ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
                        l_var->set_name("REQUEST_HEADERS:User-Agent");
                        l_var->set_value(l_buf, l_buf_len);
                        *ao_event = l_event;
                        return WAFLZ_STATUS_OK;
                }
        }
referer_check:
        // -------------------------------------------------
        // referer
        // -------------------------------------------------
        if(!m_referer_rx_blacklist ||
           !rqst_ctx::s_get_rqst_header_w_key_cb)
        {
                goto cookie_check;
        }
        l_key = "Referer";
        l_s = rqst_ctx::s_get_rqst_header_w_key_cb(&l_buf, l_buf_len, a_ctx, l_key, strlen(l_key));
        if(l_s != 0)
        {
                WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_w_key_cb: key: %s", l_key);
                goto cookie_check;
        }
        if(m_referer_rx_blacklist &&
           l_buf &&
           l_buf_len)
        {
                int32_t l_s;
                bool l_match = false;
                std::string l_rx_capture;
                l_s = m_referer_rx_blacklist->compare(l_buf, l_buf_len, &l_rx_capture);
                if(l_s >= 0)
                {
                        l_match = true;
                }
                if(l_match)
                {
                        // alloc event...
                        l_event = new ::waflz_pb::event();
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        // ---------------------------------
                        // subevent
                        // ---------------------------------
                        l_sevent->set_rule_id(430003);
                        l_sevent->set_rule_msg("Blacklist Referer match");
                        // top level rule msg
                        l_event->set_rule_msg("Blacklist Referer match");
                        l_sevent->set_rule_op_name("rx");
                        l_sevent->set_rule_op_param(m_referer_rx_blacklist->get_regex_string());
                        l_sevent->add_rule_tag("BLACKLIST/REFERER");
                        l_sevent->set_total_anomaly_score(1);
                        l_sevent->set_total_sql_injection_score(0);
                        l_sevent->set_total_xss_score(0);
                        ::waflz_pb::event_var_t* l_rule_target = l_sevent->add_rule_target();
                        l_rule_target->set_name("REQUEST_HEADERS");
                        l_rule_target->set_value("Referer");
                        ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
                        l_var->set_name("REQUEST_HEADERS:Referer");
                        l_var->set_value(l_buf, l_buf_len);
                        *ao_event = l_event;
                        return WAFLZ_STATUS_OK;
                }
        }
cookie_check:
        // -------------------------------------------------
        // cookie
        // -------------------------------------------------
        if(!m_cookie_rx_blacklist ||
           !rqst_ctx::s_get_rqst_header_w_key_cb)
        {
                return WAFLZ_STATUS_OK;
        }
        l_key = "Cookie";
        l_s = rqst_ctx::s_get_rqst_header_w_key_cb(&l_buf,
                                                  l_buf_len,
                                                  a_ctx,
                                                  l_key,
                                                  strlen(l_key));
        if(l_s != 0)
        {
                WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_w_key_cb: key: %s", l_key);
        }
        if(m_cookie_rx_blacklist &&
           l_buf &&
           l_buf_len)
        {
                int32_t l_s;
                bool l_match = false;
                std::string l_rx_capture;
                l_s = m_cookie_rx_blacklist->compare(l_buf, l_buf_len, &l_rx_capture);
                if(l_s >= 0)
                {
                        l_match = true;
                }
                if(l_match)
                {
                        // alloc event...
                        l_event = new ::waflz_pb::event();
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        // ---------------------------------
                        // subevent
                        // ---------------------------------
                        l_sevent->set_rule_id(430004);
                        l_sevent->set_rule_msg("Blacklist Cookie match");
                        // top level rule msg
                        l_event->set_rule_msg("Blacklist Cookie match");
                        l_sevent->set_rule_op_name("rx");
                        l_sevent->set_rule_op_param(m_cookie_rx_blacklist->get_regex_string());
                        l_sevent->add_rule_tag("BLACKLIST/Cookie");
                        l_sevent->set_total_anomaly_score(2);
                        l_sevent->set_total_sql_injection_score(0);
                        l_sevent->set_total_xss_score(0);
                        ::waflz_pb::event_var_t* l_rule_target = l_sevent->add_rule_target();
                        l_rule_target->set_name("REQUEST_HEADERS");
                        l_rule_target->set_value("Cookie");
                        ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
                        l_var->set_name("REQUEST_HEADERS:Cookie");
                        l_var->set_value(l_buf, l_buf_len);
                        *ao_event = l_event;
                        return WAFLZ_STATUS_OK;
                }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t acl::process_sig_settings(waflz_pb::event **ao_event, void *a_ctx)
{
        if(!ao_event)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_event = NULL;
        const char *l_key = NULL;
        const char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        int32_t l_s;
        waflz_pb::event *l_event = NULL;
        GET_RQST_DATA(rqst_ctx::s_get_rqst_method_cb);
        // -------------------------------------------------
        // country
        // -------------------------------------------------
        if(m_allowed_http_methods.size() &&
           l_buf &&
           l_buf_len)
        {
                bool l_match = false;
                if(m_allowed_http_methods.find(l_buf) != m_allowed_http_methods.end())
                {
                        l_match = true;
                }
                if(l_match)
                {
                        // alloc event...
                        l_event = new ::waflz_pb::event();
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        // ---------------------------------
                        // subevent
                        // ---------------------------------
                        l_sevent->set_rule_id(430425);
                        l_sevent->set_rule_msg("Method is not allowed by policy");
                        // top level rule msg
                        l_event->set_rule_msg("Method is not allowed by policy");
                        l_sevent->set_rule_op_name("");
                        l_sevent->set_rule_op_param("");
                        l_sevent->add_rule_tag("HTTP POLICY");
                        ::waflz_pb::event_var_t* l_rule_target = l_sevent->add_rule_target();
                        l_rule_target->set_name("REQUEST_METHOD");
                        l_rule_target->set_param(l_buf);
                        l_sevent->set_total_anomaly_score(2);
                        ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
                        l_var->set_name("REQUEST_METHOD");
                        l_var->set_value(l_buf);
                        *ao_event = l_event;
                        return WAFLZ_STATUS_OK;
                }
        }
        // Not supported yet
#if 0
        // -------------------------------------------------
        // allowed_http_versions
        // -------------------------------------------------
        if(m_allowed_http_versions.size() &&
           l_buf &&
           l_buf_len)
        {
                bool l_match = false;
                if(m_allowed_http_versions.find(l_buf) != m_allowed_http_versions.end())
                {
                        l_match = true;
                }
                if(l_match)
                {
                        // alloc event...
                        l_event = new ::waflz_pb::event();
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        // ---------------------------------
                        // subevent
                        // ---------------------------------
                        l_sevent->set_rule_id(430425);
                        l_sevent->set_rule_msg("HTTP protocol version is not allowed by policy");
                        // top level rule msg
                        l_event->set_rule_msg("Method is not allowed by policy");
                        l_sevent->set_rule_op_name("");
                        l_sevent->set_rule_op_param("");
                        l_sevent->add_rule_tag("HTTP POLICY");
                        ::waflz_pb::event_var_t* l_rule_target = l_sevent->add_rule_target();
                        l_rule_target->set_name("REQUEST_PROTOCOL");
                        l_rule_target->set_param(l_buf);
                        l_sevent->set_total_anomaly_score(2);
                        ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
                        l_var->set_name("REQUEST_PROTOCOL");
                        l_var->set_value(l_buf);
                        *ao_event = l_event;
                        return WAFLZ_STATUS_OK;
                }
        }
#endif
        GET_RQST_DATA(rqst_ctx::s_get_rqst_method_cb);
        // -------------------------------------------------
        // country
        // -------------------------------------------------
        if(m_allowed_request_content_types.size() &&
           l_buf &&
           l_buf_len)
        {
                bool l_match = false;
                if(m_allowed_request_content_types.find(l_buf) != m_allowed_request_content_types.end())
                {
                        l_match = true;
                }
                if(l_match)
                {
                        // alloc event...
                        l_event = new ::waflz_pb::event();
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        // ---------------------------------
                        // subevent
                        // ---------------------------------
                        l_sevent->set_rule_id(430425);
                        l_sevent->set_rule_msg("Request content type is not allowed by policy");
                        // top level rule msg
                        l_event->set_rule_msg("Request content type is not allowed by policy");
                        l_sevent->set_rule_op_name("");
                        l_sevent->set_rule_op_param("");
                        l_sevent->add_rule_tag("HTTP POLICY");
                        ::waflz_pb::event_var_t* l_rule_target = l_sevent->add_rule_target();
                        l_rule_target->set_name("REQUEST_HEADERS");
                        l_rule_target->set_param(l_buf);
                        l_sevent->set_total_anomaly_score(2);
                        ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
                        l_var->set_name("REQUEST_METHOD");
                        l_var->set_value(l_buf);
                        *ao_event = l_event;
                        return WAFLZ_STATUS_OK;
                }
        }
}
}
