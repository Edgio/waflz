//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    parser_json.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    04/06/2018
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
#include "parser/parser_json.h"
#include "support/ndebug.h"
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define _GET_CTX(_ctx) \
        if(!_ctx) { return 1; }\
        rqst_ctx *l_rqst_ctx = static_cast<rqst_ctx *>(_ctx);\
        if(!l_rqst_ctx->m_body_parser) { return 1; }\
        parser_json *l_parser = reinterpret_cast<parser_json *>(l_rqst_ctx->m_body_parser);
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: ****************************************************************************
//: utils
//: ****************************************************************************
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int json_add_argument(arg_list_t &ao_arg_list,
                      parser_json &a_parser_json,
                      const char *a_val,
                      unsigned a_len)
{
        // -------------------------------------------------
        // if no prefix -cannot create var name to ref arg
        // -ignore for now
        // -------------------------------------------------
        if(!a_parser_json.m_current_key)
        {
                return 1;
        }
        // -------------------------------------------------
        // create arg
        // -------------------------------------------------
        arg_t l_arg;
        // a_key == 'prefix + current_key'
        if(a_parser_json.m_prefix)
        {
                l_arg.m_key_len = asprintf(&l_arg.m_key,
                                           "%s.%s",
                                           a_parser_json.m_prefix,
                                           a_parser_json.m_current_key);
        }
        else
        {
                l_arg.m_key_len = asprintf(&l_arg.m_key,
                                           "%s",
                                           a_parser_json.m_current_key);
        }
        l_arg.m_val = strndup(a_val, a_len);
        l_arg.m_val_len = strnlen(l_arg.m_val, a_len);
        //NDBG_PRINT("ADD_ARG %.*s: %.*s\n", l_arg.m_key_len, l_arg.m_key, l_arg.m_val_len, l_arg.m_val);
        ao_arg_list.push_back(l_arg);
        return 1;
}
//: ----------------------------------------------------------------------------
//: \details callback for hash a_key values; use to define var names under ARGS.
//:          if new a_key, update current a_key a_val.
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int yajl_map_key_cb(void *a_ctx,
                           const unsigned char *a_key,
                           size_t a_len)
{
        //NDBG_PRINT("a_key: %p\n", a_key);
        //NDBG_PRINT("a_len: %d\n", (int)a_len);
        //NDBG_PRINT("a_key: %.*s\n", (int)a_len, a_key);
        _GET_CTX(a_ctx);
        // -------------------------------------------------
        // yajl does not give null-terminated strings
        // -copy data from a_key up to len
        // -------------------------------------------------
        uint32_t l_len;
        l_len = a_len > PARSER_JSON_PREFIX_LEN_MAX-1 ? PARSER_JSON_PREFIX_LEN_MAX-1 : a_len;
        strncpy((char *)l_parser->m_current_key, (char *)a_key, l_len);
        l_parser->m_current_key[l_len]='\0';
        return 1;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int yajl_null_cb(void *a_ctx)
{
        //NDBG_PRINT("a_val: NULL\n");
        _GET_CTX(a_ctx);
        arg_list_t &l_arg_list = l_rqst_ctx->m_body_arg_list;
        return json_add_argument(l_arg_list, *l_parser, "", 0);
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int yajl_bool_cb(void *a_ctx, int a_val)
{
        //NDBG_PRINT("a_val: %d\n", a_val);
        _GET_CTX(a_ctx);
        arg_list_t &l_arg_list = l_rqst_ctx->m_body_arg_list;
        if(a_val)
        {
                return json_add_argument(l_arg_list, *l_parser, "true", strlen("true"));
        }
        else
        {
                return json_add_argument(l_arg_list, *l_parser, "false", strlen("false"));
        }
}
//: ----------------------------------------------------------------------------
//: \details generic handler for numbers
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int yajl_string_cb(void *a_ctx, const unsigned char *a_val, size_t a_len)
{
        //NDBG_PRINT("a_key: %.*s\n", (int)a_len, (char *)a_val);
        _GET_CTX(a_ctx);
        arg_list_t &l_arg_list = l_rqst_ctx->m_body_arg_list;
        return json_add_argument(l_arg_list, *l_parser, (const char *)a_val, a_len);
}
//: ----------------------------------------------------------------------------
//: \details generic handler for numbers
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int yajl_number_cb(void *a_ctx, const char *a_val, size_t a_len)
{
        //NDBG_PRINT("a_key: %.*s\n", (int)a_len, (char *)a_val);
        _GET_CTX(a_ctx);
        arg_list_t &l_arg_list = l_rqst_ctx->m_body_arg_list;
        return json_add_argument(l_arg_list, *l_parser, a_val, a_len);
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int yajl_start_map_cb(void *a_ctx)
{
        _GET_CTX(a_ctx);
        // -------------------------------------------------
        // nothing in current key -top-level hash
        // -------------------------------------------------
        if(l_parser->m_current_key[0] == '\0')
        {
                return 1;
        }
        // -------------------------------------------------
        // check if inside hash ctx
        // -------------------------------------------------
        //NDBG_PRINT("l_parser->m_current_key: %s\n", (char *)l_parser->m_current_key);
        if(l_parser->m_prefix[0] == '\0')
        {
                // TODO -this sucks :(
                size_t l_max_cat_len;
                l_max_cat_len = PARSER_JSON_PREFIX_LEN_MAX - strnlen((char *)l_parser->m_prefix, PARSER_JSON_PREFIX_LEN_MAX);
                //NDBG_PRINT("l_max_cat_len: %d\n", (int)l_max_cat_len);
                if(l_max_cat_len)
                {
                        strncat((char *)l_parser->m_prefix, ".", l_max_cat_len);
                        //NDBG_PRINT("l_parser->m_prefix: %s\n", l_parser->m_prefix);
                        --l_max_cat_len;
                }
                //NDBG_PRINT("l_max_cat_len: %d\n", (int)l_max_cat_len);
                if(l_max_cat_len)
                {
                        strncat((char *)l_parser->m_prefix, (char *)l_parser->m_current_key, l_max_cat_len);
                        //NDBG_PRINT("l_parser->m_prefix: %s\n", l_parser->m_prefix);
                }
        }
        else
        {
                strncpy((char *)l_parser->m_prefix, (char *)l_parser->m_current_key, PARSER_JSON_PREFIX_LEN_MAX);
                //NDBG_PRINT("l_parser->m_prefix: %s\n", l_parser->m_prefix);
        }
        return 1;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int yajl_end_map_cb(void *a_ctx)
{
        _GET_CTX(a_ctx);
        // -------------------------------------------------
        // end of top level hash
        // -------------------------------------------------
        if(!l_parser->m_prefix[0] == '\0')
        {
                return 1;
        }
        // -------------------------------------------------
        // current prefix include separator char???
        // top-level hash keys have no sep in var name
        // -------------------------------------------------
        char *l_sep = (char *)NULL;
        l_sep = strrchr((char*)l_parser->m_prefix, '.');
        //NDBG_PRINT("l_parser->m_prefix: %s\n", l_parser->m_prefix);
        //NDBG_PRINT("l_sep:              %p\n", l_sep);
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if(l_sep)
        {
                strncpy((char*)l_parser->m_prefix, (char *)(l_sep - (char *)l_parser->m_prefix), PARSER_JSON_PREFIX_LEN_MAX);
                //NDBG_PRINT("l_parser->m_prefix: %s\n", l_parser->m_prefix);
                strncpy((char*)l_parser->m_current_key, l_sep + 1, PARSER_JSON_PREFIX_LEN_MAX);
        }
        else
        {
                strncpy((char*)l_parser->m_current_key, (char*)l_parser->m_prefix, PARSER_JSON_PREFIX_LEN_MAX);
                memset(l_parser->m_prefix, 0, sizeof(l_parser->m_prefix));
                l_parser->m_prefix[0] = '\0';
        }
        return 1;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
parser_json::parser_json(rqst_ctx *a_rqst_ctx):
        parser(a_rqst_ctx),
        m_handle(),
        m_status(),
        m_error(NULL),
        m_prefix(),
        m_current_key()
{
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
parser_json::~parser_json()
{
        if(m_handle)
        {
                yajl_free(m_handle);
                m_handle = NULL;
        }
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t parser_json::init()
{
        // -------------------------------------------------
        // setup callbacks
        // -------------------------------------------------
        static yajl_callbacks s_callbacks = {
                yajl_null_cb,
                yajl_bool_cb,
                NULL,              // yajl_integer,
                NULL,              // yajl_double,
                yajl_number_cb,
                yajl_string_cb,
                yajl_start_map_cb,
                yajl_map_key_cb,
                yajl_end_map_cb,
                NULL,              // yajl_start_array
                NULL               // yajl_end_array
        };
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        memset(m_prefix, 0, sizeof(m_prefix));
        memset(m_current_key, 0, sizeof(m_current_key));
        m_prefix[0] = '\0';
        m_current_key[0] = '\0';
        // -------------------------------------------------
        // yajl init
        // -------------------------------------------------
        // -------------------------------------------------
        // TODO: make UTF8 validation optional as deptends
        //       on Content-Encoding
        // -------------------------------------------------
        m_handle = yajl_alloc(&s_callbacks, NULL, m_rqst_ctx);
        yajl_config(m_handle, yajl_allow_partial_values, 1);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t parser_json::process_chunk(const char *a_buf, uint32_t a_len)
{
        //NDBG_PRINT("a_buf: %p\n", a_buf);
        //mem_display((const uint8_t *)a_buf, a_len);
        m_status = yajl_parse(m_handle, (const unsigned char *)a_buf, a_len);
        if(m_status != yajl_status_ok)
        {
                // TODO get error???
                //const unsigned char *l_err = yajl_get_error(m_handle, 1, (const unsigned char *)a_buf, a_len);
                //NDBG_PRINT("error: %d. reason: \n%s\n", m_status, l_err);
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t parser_json::finish(void)
{
        m_status = yajl_complete_parse(m_handle);
        if(m_status != yajl_status_ok)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
}
