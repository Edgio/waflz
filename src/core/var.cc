//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    var.cc
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
#include "waflz/rqst_ctx.h"
#include "core/var.h"
#include "op/regex.h"
#include <vector>
// ---------------------------------------------------------
// *********************************************************
// xml support
// *********************************************************
// ---------------------------------------------------------
#include "parser/parser_xml.h"
#include <libxml/xpathInternals.h>
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define GET_VAR(_type) \
        static int32_t _get_var_##_type(const_arg_list_t &ao_list, \
                                        uint32_t &ao_count, \
                                        const waflz_pb::variable_t &a_var, \
                                        rqst_ctx *a_ctx)
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: ****************************************************************************
//:                            U T I L S
//: ****************************************************************************
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void get_matched(const_arg_list_t &ao_list,
                        uint32_t &ao_count,
                        const ::waflz_pb::variable_t &a_var,
                        const arg_list_t &a_list,
                        bool a_is_count,
                        bool a_is_key)
{
        // -------------------------------------------------
        // get negated fields
        // -------------------------------------------------
        typedef const ::waflz_pb::variable_t_match_t _m_t;
        typedef std::list <const _m_t *> _m_list_t;
        _m_list_t l_ng_list;
        for(int32_t i_m = 0; i_m < a_var.match_size(); ++i_m)
        {
                const ::waflz_pb::variable_t_match_t &l_match = a_var.match(i_m);
                if(l_match.is_negated() &&
                   l_match.has_value())
                {
                        l_ng_list.push_back(&l_match);
                }
        }
        // -------------------------------------------------
        // match loop
        // -------------------------------------------------
        for(int32_t i_m = 0; i_m < a_var.match_size(); ++i_m)
        {
                // -----------------------------------------
                // check match
                // -----------------------------------------
                const ::waflz_pb::variable_t_match_t &l_match = a_var.match(i_m);
                if(l_match.is_negated())
                {
                        continue;
                }
                for(arg_list_t::const_iterator i_k = a_list.begin();
                    i_k != a_list.end();
                    ++i_k)
                {
                        bool l_matched = false;
                        const char *l_m;
                        uint32_t l_m_len;
                        l_m = i_k->m_key;
                        l_m_len = i_k->m_key_len;
                        // ---------------------------------
                        // any
                        // ---------------------------------
                        if(!l_match.has_value())
                        {
                                l_matched = true;
                        }
                        // ---------------------------------
                        // regex
                        // ---------------------------------
                        else if(l_match.is_regex() &&
                                l_match.has__reserved_1())
                        {
                                regex *l_rx = (regex *)(l_match._reserved_1());
                                int32_t l_s;
                                // get capture???
                                l_s = l_rx->compare(l_m, l_m_len, NULL);
                                if(l_s > 0)
                                {
                                        l_matched = true;
                                }
                        }
                        // ---------------------------------
                        // str comp
                        // ---------------------------------
                        else
                        {
                                const std::string &l_match_val = l_match.value();
                                if(l_match_val.length() == l_m_len)
                                {
                                        if(strncasecmp(l_match_val.c_str(), l_m, l_m_len) == 0)
                                        {
                                                l_matched = true;
                                        }
                                }
                        }
                        // ---------------------------------
                        // check negated...
                        // ---------------------------------
                        if(l_ng_list.size())
                        {
                                for(_m_list_t::const_iterator i_ng_m = l_ng_list.begin();
                                    i_ng_m != l_ng_list.end();
                                    ++i_ng_m)
                                {
                                        const ::waflz_pb::variable_t_match_t &l_ng_m = **i_ng_m;
                                        if(!l_ng_m.has_value())
                                        {
                                                continue;
                                        }
                                        // -----------------
                                        // regex
                                        // -----------------
                                        if(l_ng_m.is_regex() &&
                                           l_ng_m.has__reserved_1())
                                        {
                                                regex *l_rx = (regex *)(l_ng_m._reserved_1());
                                                int32_t l_s;
                                                // get capture???
                                                l_s = l_rx->compare(l_m, l_m_len, NULL);
                                                if(l_s > 0)
                                                {
                                                        l_matched = false;
                                                }
                                        }
                                        // -----------------
                                        // string
                                        // -----------------
                                        else
                                        {
                                                const std::string &l_mv = l_ng_m.value();
                                                if(l_mv.length() == l_m_len)
                                                {
                                                        if(strncasecmp(l_mv.c_str(), l_m, l_m_len) == 0)
                                                        {
                                                                l_matched = false;
                                                        }
                                                }
                                        }
                                }
                        }
                        // ---------------------------------
                        // if no match...
                        // ---------------------------------
                        if(!l_matched)
                        {
                                continue;
                        }
                        // ---------------------------------
                        // count...
                        // ---------------------------------
                        if(a_is_count)
                        {
                                ++ao_count;
                                continue;
                        }
                        // ---------------------------------
                        // append
                        // ---------------------------------
                        const_arg_t l_data;
                        l_data.m_key = i_k->m_key;
                        l_data.m_key_len = i_k->m_key_len;
                        if(a_is_key)
                        {
                                l_data.m_val = i_k->m_key;
                                l_data.m_val_len = i_k->m_key_len;
                        }
                        else
                        {
                                l_data.m_val = i_k->m_val;
                                l_data.m_val_len = i_k->m_val_len;
                        }
                        ao_list.push_back(l_data);
                }
        }
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void get_matched_const(const_arg_list_t &ao_list,
                              uint32_t &ao_count,
                              const ::waflz_pb::variable_t &a_var,
                              const const_arg_list_t &a_list,
                              bool a_is_count,
                              bool a_is_key)
{
        // -------------------------------------------------
        // get negated fields
        // -------------------------------------------------
        typedef const ::waflz_pb::variable_t_match_t _m_t;
        typedef std::list <const _m_t *> _m_list_t;
        _m_list_t l_ng_list;
        for(int32_t i_m = 0; i_m < a_var.match_size(); ++i_m)
        {
                const ::waflz_pb::variable_t_match_t &l_match = a_var.match(i_m);
                if(l_match.is_negated() &&
                   l_match.has_value())
                {
                        l_ng_list.push_back(&l_match);
                }
        }
        // -------------------------------------------------
        // match loop
        // -------------------------------------------------
        for(int32_t i_m = 0; i_m < a_var.match_size(); ++i_m)
        {
                // -----------------------------------------
                // check match
                // -----------------------------------------
                const ::waflz_pb::variable_t_match_t &l_match = a_var.match(i_m);
                if(l_match.is_negated())
                {
                        continue;
                }
                for(const_arg_list_t::const_iterator i_k = a_list.begin();
                    i_k != a_list.end();
                    ++i_k)
                {
                        bool l_matched = false;
                        const char *l_m;
                        uint32_t l_m_len;
                        l_m = i_k->m_key;
                        l_m_len = i_k->m_key_len;
                        // ---------------------------------
                        // any
                        // ---------------------------------
                        if(!l_match.has_value())
                        {
                                l_matched = true;
                        }
                        // ---------------------------------
                        // regex
                        // ---------------------------------
                        else if(l_match.is_regex() &&
                                l_match.has__reserved_1())
                        {
                                regex *l_rx = (regex *)(l_match._reserved_1());
                                int32_t l_s;
                                // get capture???
                                l_s = l_rx->compare(l_m, l_m_len, NULL);
                                if(l_s > 0)
                                {
                                        l_matched = true;
                                }
                        }
                        // ---------------------------------
                        // str comp
                        // ---------------------------------
                        else
                        {
                                const std::string &l_match_val = l_match.value();
                                if(l_match_val.length() == l_m_len)
                                {
                                        if(strncasecmp(l_match_val.c_str(), l_m, l_m_len) == 0)
                                        {
                                                l_matched = true;
                                        }
                                }
                        }
                        // ---------------------------------
                        // check negated...
                        // ---------------------------------
                        if(l_ng_list.size())
                        {
                                for(_m_list_t::const_iterator i_ng_m = l_ng_list.begin();
                                    i_ng_m != l_ng_list.end();
                                    ++i_ng_m)
                                {
                                        const ::waflz_pb::variable_t_match_t &l_ng_m = **i_ng_m;
                                        if(!l_ng_m.has_value())
                                        {
                                                continue;
                                        }
                                        // -----------------
                                        // regex
                                        // -----------------
                                        if(l_ng_m.is_regex() &&
                                           l_ng_m.has__reserved_1())
                                        {
                                                regex *l_rx = (regex *)(l_ng_m._reserved_1());
                                                int32_t l_s;
                                                // get capture???
                                                l_s = l_rx->compare(l_m, l_m_len, NULL);
                                                if(l_s > 0)
                                                {
                                                        l_matched = false;
                                                }
                                        }
                                        // -----------------
                                        // string
                                        // -----------------
                                        else
                                        {
                                                const std::string &l_mv = l_ng_m.value();
                                                if(l_mv.length() == l_m_len)
                                                {
                                                        if(strncasecmp(l_mv.c_str(), l_m, l_m_len) == 0)
                                                        {
                                                                l_matched = false;
                                                        }
                                                }
                                        }
                                }
                        }
                        // ---------------------------------
                        // if no match...
                        // ---------------------------------
                        if(!l_matched)
                        {
                                continue;
                        }
                        // ---------------------------------
                        // count...
                        // ---------------------------------
                        if(a_is_count)
                        {
                                ++ao_count;
                                continue;
                        }
                        // ---------------------------------
                        // append
                        // ---------------------------------
                        const_arg_t l_data;
                        l_data.m_key = i_k->m_key;
                        l_data.m_key_len = i_k->m_key_len;
                        if(a_is_key)
                        {
                                l_data.m_val = i_k->m_key;
                                l_data.m_val_len = i_k->m_key_len;
                        }
                        else
                        {
                                l_data.m_val = i_k->m_val;
                                l_data.m_val_len = i_k->m_val_len;
                        }
                        ao_list.push_back(l_data);
                }
        }
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void add_vars(const_arg_list_t &ao_list,
                     uint32_t &ao_count,
                     const arg_list_t &a_list,
                     bool a_is_count,
                     bool a_is_key)
{
        for(arg_list_t::const_iterator i_k = a_list.begin();
            i_k != a_list.end();
            ++i_k)
        {
                if(a_is_count)
                {
                        ++ao_count;
                        continue;
                }
                const_arg_t l_data;
                l_data.m_key = i_k->m_key;
                l_data.m_key_len = i_k->m_key_len;
                if(a_is_key)
                {
                        l_data.m_val = i_k->m_key;
                        l_data.m_val_len = i_k->m_key_len;
                }
                else
                {
                        l_data.m_val = i_k->m_val;
                        l_data.m_val_len = i_k->m_val_len;
                }
                ao_list.push_back(l_data);
        }
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void add_vars_const(const_arg_list_t &ao_list,
                           uint32_t &ao_count,
                           const const_arg_list_t &a_list,
                           bool a_is_count,
                           bool a_is_key)
{
        for(const_arg_list_t::const_iterator i_k = a_list.begin();
            i_k != a_list.end();
            ++i_k)
        {
                if(a_is_count)
                {
                        ++ao_count;
                        continue;
                }
                const_arg_t l_data;
                l_data.m_key = i_k->m_key;
                l_data.m_key_len = i_k->m_key_len;
                if(a_is_key)
                {
                        l_data.m_val = i_k->m_key;
                        l_data.m_val_len = i_k->m_key_len;
                }
                else
                {
                        l_data.m_val = i_k->m_val;
                        l_data.m_val_len = i_k->m_val_len;
                }
                ao_list.push_back(l_data);
        }
}
//: ----------------------------------------------------------------------------
//: ****************************************************************************
//:                          G E T   V A R S
//: ****************************************************************************
//: ----------------------------------------------------------------------------
#define _ADD_VAR(_str, _from) do { \
        const_arg_t l_data; \
        l_data.m_key = _str; \
        l_data.m_key_len = sizeof(_str) - 1; \
        l_data.m_val = _from.m_data; \
        l_data.m_val_len = _from.m_len; \
        ao_list.push_back(l_data); \
        }while(0)
//: ----------------------------------------------------------------------------
//: \details: REMOTE_ADDR
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(REMOTE_ADDR)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // TODO -handle counts!
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        _ADD_VAR("REMOTE_ADDR", a_ctx->m_src_addr);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: REQUEST_PROTOCOL
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(REQUEST_PROTOCOL)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // TODO -handle counts!
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        _ADD_VAR("REQUEST_PROTOCOL", a_ctx->m_protocol);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: REQUEST_LINE
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(REQUEST_LINE)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // TODO -handle counts!
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        _ADD_VAR("REQUEST_LINE", a_ctx->m_line);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: REQUEST_METHOD
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(REQUEST_METHOD)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // TODO -handle counts!
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        _ADD_VAR("REQUEST_METHOD", a_ctx->m_method);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: REQUEST_URI_RAW
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(REQUEST_URI_RAW)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // TODO -handle counts!
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        _ADD_VAR("REQUEST_URI_RAW", a_ctx->m_url);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: REQUEST_URI
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(REQUEST_URI)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // TODO -handle counts!
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        _ADD_VAR("REQUEST_URI", a_ctx->m_uri);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: REQUEST_FILENAME
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(REQUEST_FILENAME)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // TODO -handle counts!
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        _ADD_VAR("REQUEST_FILENAME", a_ctx->m_path);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: REQUEST_BASENAME
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(REQUEST_BASENAME)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        _ADD_VAR("REQUEST_BASENAME", a_ctx->m_base);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: QUERY_STRING
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(QUERY_STRING)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // TODO -handle counts!
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        _ADD_VAR("QUERY_STRING", a_ctx->m_query_str);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(ARGS)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        if(!a_var.match_size() ||
           ((a_var.match_size() == 1) &&
            !a_var.match(0).has_value()))
        {
                add_vars(ao_list,
                         ao_count,
                         a_ctx->m_query_arg_list,
                         a_var.is_count(),
                         false);
                add_vars(ao_list,
                         ao_count,
                         a_ctx->m_body_arg_list,
                         a_var.is_count(),
                         false);
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // query args
        // -------------------------------------------------
        get_matched(ao_list,
                    ao_count,
                    a_var,
                    a_ctx->m_query_arg_list,
                    a_var.is_count(),
                    false);
        // -------------------------------------------------
        // post args
        // -------------------------------------------------
        get_matched(ao_list,
                    ao_count,
                    a_var,
                    a_ctx->m_body_arg_list,
                    a_var.is_count(),
                    false);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(ARGS_NAMES)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        if(!a_var.match_size() ||
           ((a_var.match_size() == 1) &&
            !a_var.match(0).has_value()))
        {
                add_vars(ao_list,
                         ao_count,
                         a_ctx->m_query_arg_list,
                         a_var.is_count(),
                         true);
                add_vars(ao_list,
                         ao_count,
                         a_ctx->m_body_arg_list,
                         a_var.is_count(),
                         true);
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // query args
        // -------------------------------------------------
        get_matched(ao_list,
                    ao_count,
                    a_var,
                    a_ctx->m_query_arg_list,
                    a_var.is_count(),
                    true);
        // -------------------------------------------------
        // post args
        // -------------------------------------------------
        get_matched(ao_list,
                    ao_count,
                    a_var,
                    a_ctx->m_body_arg_list,
                    a_var.is_count(),
                    true);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(ARGS_GET)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        if(!a_var.match_size() ||
           ((a_var.match_size() == 1) &&
            !a_var.match(0).has_value()))
        {
                add_vars(ao_list,
                         ao_count,
                         a_ctx->m_query_arg_list,
                         a_var.is_count(),
                         false);
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get query arg values
        // -------------------------------------------------
        get_matched(ao_list,
                    ao_count,
                    a_var,
                    a_ctx->m_query_arg_list,
                    a_var.is_count(),
                         false);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(ARGS_GET_NAMES)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        if(!a_var.match_size() ||
           ((a_var.match_size() == 1) &&
            !a_var.match(0).has_value()))
        {
                add_vars(ao_list,
                         ao_count,
                         a_ctx->m_query_arg_list,
                         a_var.is_count(),
                         true);
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get query arg values
        // -------------------------------------------------
        get_matched(ao_list,
                    ao_count,
                    a_var,
                    a_ctx->m_query_arg_list,
                    a_var.is_count(),
                    true);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(ARGS_POST)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        if(!a_var.match_size() ||
           ((a_var.match_size() == 1) &&
            !a_var.match(0).has_value()))
        {
                add_vars(ao_list,
                         ao_count,
                         a_ctx->m_body_arg_list,
                         a_var.is_count(),
                         false);
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get query arg values
        // -------------------------------------------------
        get_matched(ao_list,
                    ao_count,
                    a_var,
                    a_ctx->m_body_arg_list,
                    a_var.is_count(),
                    false);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(ARGS_POST_NAMES)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        if(!a_var.match_size() ||
           ((a_var.match_size() == 1) &&
            !a_var.match(0).has_value()))
        {
                add_vars(ao_list,
                         ao_count,
                         a_ctx->m_body_arg_list,
                         a_var.is_count(),
                         true);
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get query arg values
        // -------------------------------------------------
        get_matched(ao_list,
                    ao_count,
                    a_var,
                    a_ctx->m_body_arg_list,
                    a_var.is_count(),
                    true);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: ARGS_COMBINED_SIZE: Total size of all request parameters combined
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(ARGS_COMBINED_SIZE)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        size_t l_arg_len = 0;
        // -------------------------------------------------
        // query calc
        // -------------------------------------------------
        for(arg_list_t::const_iterator i_k = a_ctx->m_query_arg_list.begin();
            i_k != a_ctx->m_query_arg_list.end();
            ++i_k)
        {
                l_arg_len += i_k->m_val_len;
                l_arg_len += i_k->m_key_len;
        }
        // -------------------------------------------------
        // post body calc
        // -------------------------------------------------
        for(arg_list_t::const_iterator i_k = a_ctx->m_body_arg_list.begin();
            i_k != a_ctx->m_body_arg_list.end();
            ++i_k)
        {
                l_arg_len += i_k->m_val_len;
                l_arg_len += i_k->m_key_len;
        }
        const_arg_t l_data;
        l_data.m_key = "ARGS_COMBINED_SIZE";
        l_data.m_key_len = sizeof("ARGS_COMBINED_SIZE") - 1;
        l_data.m_val = "ARGS_COMBINED_SIZE";
        l_data.m_val_len = l_arg_len;
        ao_list.push_back(l_data);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: REQUEST_COOKIES
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(REQUEST_COOKIES)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        if(!a_var.match_size() ||
           ((a_var.match_size() == 1) &&
            !a_var.match(0).has_value()))
        {
                add_vars_const(ao_list,
                               ao_count,
                               a_ctx->m_cookie_list,
                               a_var.is_count(),
                               false);
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get query arg values
        // -------------------------------------------------
        get_matched_const(ao_list,
                          ao_count,
                          a_var,
                          a_ctx->m_cookie_list,
                          a_var.is_count(),
                          false);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: REQUEST_COOKIES_NAMES
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(REQUEST_COOKIES_NAMES)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        if(!a_var.match_size() ||
           ((a_var.match_size() == 1) &&
            !a_var.match(0).has_value()))
        {
                add_vars_const(ao_list,
                               ao_count,
                               a_ctx->m_cookie_list,
                               a_var.is_count(),
                               true);
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get matched cookie name
        // --------------------------s-----------------------
        get_matched_const(ao_list,
                          ao_count,
                          a_var,
                          a_ctx->m_cookie_list,
                          a_var.is_count(),
                          true);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: REQUEST_HEADERS
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(REQUEST_HEADERS)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        if(!a_var.match_size() ||
           ((a_var.match_size() == 1) &&
            !a_var.match(0).has_value()))
        {
                add_vars_const(ao_list,
                               ao_count,
                               a_ctx->m_header_list,
                               a_var.is_count(),
                               false);
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get matches
        // -------------------------------------------------
        get_matched_const(ao_list,
                          ao_count,
                          a_var,
                          a_ctx->m_header_list,
                          a_var.is_count(),
                          false);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: REQUEST_HEADERS_NAMES
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(REQUEST_HEADERS_NAMES)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        if(!a_var.match_size() ||
           ((a_var.match_size() == 1) &&
            !a_var.match(0).has_value()))
        {
                add_vars_const(ao_list,
                               ao_count,
                               a_ctx->m_header_list,
                               a_var.is_count(),
                               true);
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get matches
        // -------------------------------------------------
        get_matched_const(ao_list,
                          ao_count,
                          a_var,
                          a_ctx->m_header_list,
                          a_var.is_count(),
                          true);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TX
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(TX)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        //NDBG_PRINT("a_var: %s\n", a_var.ShortDebugString().c_str());
        if(!a_var.match_size())
        {
                NDBG_PRINT("no tx variable specified\n");
                return WAFLZ_STATUS_OK;
        }
        for(int32_t i_m = 0; i_m < a_var.match_size(); ++i_m)
        {
                // -----------------------------------------
                // has value???
                // -----------------------------------------
                if(!a_var.match(i_m).has_value())
                {
                        continue;
                }
                // -----------------------------------------
                // in map???
                // -----------------------------------------
                const std::string &l_val = a_var.match(i_m).value();
                cx_map_t::const_iterator i_tx = a_ctx->m_cx_tx_map.find(l_val);
                if(i_tx == a_ctx->m_cx_tx_map.end())
                {
                        continue;
                }
                const std::string &l_key = i_tx->first;
                const std::string &l_str = i_tx->second;
                uint32_t l_len = l_str.length();
                // -----------------------------------------
                // is count???
                // -----------------------------------------
                if(a_var.is_count())
                {
                        if(l_len > 0)
                        {
                                ++ao_count;
                        }
                        continue;
                }
                // -----------------------------------------
                // If the variable is not set
                // Dont push anything. An empty val can
                // match with rx. Dont want to do that
                // -----------------------------------------
                if(l_len <= 0)
                {
                        continue;
                }
                const_arg_t l_data;
                l_data.m_key = l_key.c_str();
                l_data.m_key_len = l_key.length();
                l_data.m_val = l_str.c_str();
                l_data.m_val_len = l_len;
                ao_list.push_back(l_data);
                //NDBG_PRINT("TX(found): %s: -> %s\n", l_val.c_str(), l_str.c_str());
        }
        //NDBG_PRINT("%svar%s: %s%s%s\n",
        //           ANSI_COLOR_BG_WHITE, ANSI_COLOR_OFF,
        //           ANSI_COLOR_FG_WHITE, a_var.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: MATCHED_VAR
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(MATCHED_VAR)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // last matched var...
        const_arg_t l_data;
        l_data.m_key = a_ctx->m_cx_matched_var_name.c_str();
        l_data.m_key_len = a_ctx->m_cx_matched_var_name.length();
        l_data.m_val = a_ctx->m_cx_matched_var.c_str();
        l_data.m_val_len = a_ctx->m_cx_matched_var.length();
        ao_list.push_back(l_data);
        //NDBG_PRINT("get var matched var = %s\n", l_data.m_data);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: MATCHED_VAR
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(MATCHED_VAR_NAME)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // last matched var...
        const_arg_t l_data;
        l_data.m_key = a_ctx->m_cx_matched_var_name.c_str();
        l_data.m_key_len = a_ctx->m_cx_matched_var_name.length();
        l_data.m_val = a_ctx->m_cx_matched_var_name.c_str();
        l_data.m_val_len = a_ctx->m_cx_matched_var_name.length();
        ao_list.push_back(l_data);
        //NDBG_PRINT("get var matched var = %s\n", l_data.m_data);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: MATCHED_VAR
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(MATCHED_VARS)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // last matched var...
        // TODO -get all matches...
        const_arg_t l_data;
        l_data.m_key = a_ctx->m_cx_matched_var_name.c_str();
        l_data.m_key_len = a_ctx->m_cx_matched_var_name.length();
        l_data.m_val = a_ctx->m_cx_matched_var.c_str();
        l_data.m_val_len = a_ctx->m_cx_matched_var.length();
        ao_list.push_back(l_data);
        //NDBG_PRINT("get var matched var = %s\n", l_data.m_data);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: MATCHED_VAR
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(MATCHED_VARS_NAMES)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // last matched var...
        // TODO -get all matches...
        const_arg_t l_data;
        l_data.m_key = a_ctx->m_cx_matched_var_name.c_str();
        l_data.m_key_len = a_ctx->m_cx_matched_var_name.length();
        l_data.m_val = a_ctx->m_cx_matched_var_name.c_str();
        l_data.m_val_len = a_ctx->m_cx_matched_var_name.length();
        ao_list.push_back(l_data);
        //NDBG_PRINT("get var matched var = %s\n", l_data.m_data);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: REQUEST_BODY
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(REQUEST_BODY)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // unconditional match
        // -------------------------------------------------
        const_arg_t l_data;
        l_data.m_key = "REQUEST_BODY";
        l_data.m_key_len = sizeof("REQUEST_BODY") - 1;
        l_data.m_val = a_ctx->m_body_data;
        l_data.m_val_len = a_ctx->m_body_len;
        ao_list.push_back(l_data);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: REQBODY_ERROR
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(REQBODY_ERROR)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // in map???
        // -------------------------------------------------
        cx_map_t::const_iterator i_tx = a_ctx->m_cx_tx_map.find("REQBODY_ERROR");
        if(i_tx == a_ctx->m_cx_tx_map.end())
        {
                return WAFLZ_STATUS_OK;;
        }
        const std::string &l_key = i_tx->first;
        const std::string &l_str = i_tx->second;
        uint32_t l_len = sizeof("REQBODY_ERROR") - 1;
        // -------------------------------------------------
        // is count???
        // -------------------------------------------------
        if(a_var.is_count())
        {
                if(l_len > 0)
                {
                        ++ao_count;
                }
                return WAFLZ_STATUS_OK;
        }
        const_arg_t l_data;
        l_data.m_key = l_key.c_str();
        l_data.m_key_len = l_key.length();
        l_data.m_val = l_str.c_str();
        l_data.m_val_len = l_len;
        ao_list.push_back(l_data);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: XML
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
GET_VAR(XML)
{
        if(!a_ctx->m_body_parser ||
           (a_ctx->m_body_parser->get_type() != PARSER_XML))
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // invocation w/o xpath for functions that
        // manipulate the doc tree
        // -------------------------------------------------
        if(!a_var.match_size() ||
           a_var.match(0).value().empty())
        {
                const_arg_t l_data;
                l_data.m_key = "XML";
                l_data.m_key_len = sizeof("XML") - 1;
                l_data.m_val = "[XML document tree]";
                l_data.m_val_len = sizeof("[XML document tree]") - 1;
                ao_list.push_back(l_data);
                ao_count = 1;
                return WAFLZ_STATUS_OK;
        }
        // Check for negated xml variable
        // We only support yanking out the whole xml and not any specific var
        // e.g !xml:/*
        for(int32_t i_m = 0; i_m < a_var.match_size(); ++i_m)
        {
                // -----------------------------------------
                // check match
                // -----------------------------------------
                const ::waflz_pb::variable_t_match_t &l_match = a_var.match(i_m);
                if(l_match.is_negated() &&
                   l_match.has_value())
                {
                        if(l_match.value() == "/*")
                        {
                                return WAFLZ_STATUS_OK;
                        }
                }
        }
        // -------------------------------------------------
        // TODO -not xmlns meta is unhandled here...
        //       was unused in most rulesets...
        // -------------------------------------------------
        ao_count = 0;
        // use first only
        const char *l_xpath_str = a_var.match(0).value().c_str();
        // -------------------------------------------------
        // *************************************************
        // xml optimization -lookup in cache map
        // *************************************************
        // -------------------------------------------------
        xpath_cache_map_t::const_iterator i_xp;
        if(a_ctx->m_xpath_cache_map &&
           ((i_xp = a_ctx->m_xpath_cache_map->find(l_xpath_str)) != a_ctx->m_xpath_cache_map->end()))
        {
                for(xpath_arg_list_t::const_iterator i_s = i_xp->second.begin();
                    i_s != i_xp->second.end();
                    ++i_s)
                {
                        ao_list.push_back(*i_s);
                        ++ao_count;
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // process xpath
        // -------------------------------------------------
        const xmlChar* l_xpath_expr = (const xmlChar*)a_var.match(0).value().c_str();
        xmlXPathContextPtr l_xpath_ctx;
        parser_xml &l_parser_xml = *((parser_xml *)a_ctx->m_body_parser);
        l_xpath_ctx = xmlXPathNewContext(l_parser_xml.m_doc);
        if(l_xpath_ctx == NULL)
        {
                // TODO log error??? "XML: Unable to create new XPath context."
                return WAFLZ_STATUS_ERROR;
        }
        xmlXPathObjectPtr l_xpath_obj;
        l_xpath_obj = xmlXPathEvalExpression(l_xpath_expr, l_xpath_ctx);
        if(l_xpath_obj == NULL)
        {
                // TODO log error??? "XML: Unable to evaluate xpath expression."
                xmlXPathFreeContext(l_xpath_ctx);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // eval xpath expr
        // -------------------------------------------------
        xmlNodeSetPtr l_nodes;
        l_nodes = l_xpath_obj->nodesetval;
        if(l_nodes == NULL)
        {
                xmlXPathFreeObject(l_xpath_obj);
                xmlXPathFreeContext(l_xpath_ctx);
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // *************************************************
        // xml optimization -setup if needed
        // *************************************************
        // -------------------------------------------------
        if(!a_ctx->m_xpath_cache_map)
        {
                a_ctx->m_xpath_cache_map = new xpath_cache_map_t();
        }
        if(a_ctx->m_xpath_cache_map->find(l_xpath_str) == a_ctx->m_xpath_cache_map->end())
        {
                const_arg_list_t l_list;
                (*a_ctx->m_xpath_cache_map)[l_xpath_str] = l_list;
        }
        // -------------------------------------------------
        // create var per node result
        // -------------------------------------------------
        for(int32_t i_n = 0; i_n < l_nodes->nodeNr; ++i_n)
        {
                char *l_content = NULL;
                l_content = (char *)xmlNodeGetContent(l_nodes->nodeTab[i_n]);
                if(l_content == NULL)
                {
                        continue;
                }
                ++ao_count;
                const_arg_t l_data;
                l_data.m_key = a_var.match(0).value().c_str();
                l_data.m_key_len = a_var.match(0).value().length();
                l_data.m_val = l_content;
                l_data.m_val_len = strlen(l_content);
                ao_list.push_back(l_data);
                // -----------------------------------------
                // *****************************************
                // xml optimization -add to cache
                // *****************************************
                // -----------------------------------------
                (*a_ctx->m_xpath_cache_map)[l_xpath_str].push_back(l_data);
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        xmlXPathFreeObject(l_xpath_obj);
        xmlXPathFreeContext(l_xpath_ctx);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define INIT_GET_VAR(_type) \
        s_var_cb_vector[waflz_pb::variable_t_type_t_##_type] = _get_var_##_type
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef std::vector <get_var_t> get_var_cb_vector_t;
//: ----------------------------------------------------------------------------
//: vector...
//: ----------------------------------------------------------------------------
static get_var_cb_vector_t s_var_cb_vector = get_var_cb_vector_t(1024);
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void init_var_cb_vector(void)
{
        INIT_GET_VAR(ARGS);
        INIT_GET_VAR(ARGS_NAMES);
        INIT_GET_VAR(ARGS_GET);
        INIT_GET_VAR(ARGS_GET_NAMES);
        INIT_GET_VAR(ARGS_POST);
        INIT_GET_VAR(ARGS_POST_NAMES);
        INIT_GET_VAR(ARGS_COMBINED_SIZE);
        INIT_GET_VAR(QUERY_STRING);
        INIT_GET_VAR(REQUEST_BASENAME);
        INIT_GET_VAR(REQUEST_FILENAME);
        INIT_GET_VAR(REQUEST_COOKIES);
        INIT_GET_VAR(REQUEST_COOKIES_NAMES);
        INIT_GET_VAR(REQUEST_HEADERS);
        INIT_GET_VAR(REQUEST_HEADERS_NAMES);
        INIT_GET_VAR(REQUEST_LINE);
        INIT_GET_VAR(REQUEST_METHOD);
        INIT_GET_VAR(REQUEST_PROTOCOL);
        INIT_GET_VAR(REQUEST_URI);
        INIT_GET_VAR(REQUEST_URI_RAW);
        // -------------------------------------------------
        // variables
        // -------------------------------------------------
        INIT_GET_VAR(TX);
        //INIT_GET_VAR(IP);
        INIT_GET_VAR(MATCHED_VAR);
        INIT_GET_VAR(MATCHED_VAR_NAME);
        INIT_GET_VAR(MATCHED_VARS);
        INIT_GET_VAR(MATCHED_VARS_NAMES);
        // -------------------------------------------------
        // req body parse failure message
        // -------------------------------------------------
        INIT_GET_VAR(REQBODY_ERROR);
        // -------------------------------------------------
        // mutipart/form-data variables...
        // -------------------------------------------------
        //INIT_GET_VAR(FILES);
        //INIT_GET_VAR(FILES_COMBINED_SIZE);
        //INIT_GET_VAR(FILES_NAMES);
        //INIT_GET_VAR(MULTIPART_STRICT_ERROR);
        //INIT_GET_VAR(MULTIPART_UNMATCHED_BOUNDARY);
        // -------------------------------------------------
        // xml body
        // -------------------------------------------------
        INIT_GET_VAR(XML);
        // -------------------------------------------------
        // urlencoded body
        // -------------------------------------------------
        INIT_GET_VAR(REQUEST_BODY);
        INIT_GET_VAR(REMOTE_ADDR);
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
get_var_t get_var_cb(waflz_pb::variable_t_type_t a_type)
{
        return s_var_cb_vector[a_type];
}

}
