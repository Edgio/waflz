//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    redis_db.cc
//: \details: redis db kv implementation for waflz
//: \author:  Reed P. Morrison
//: \date:    06/05/2018
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
#include "waflz/redis_db.h"
#include "waflz/def.h"
#include <stdlib.h>
#include <string.h>
#include <hiredis/hiredis.h>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
redis_db::redis_db(void):
        kv_db(),
        m_ctx(NULL),
        m_config_host("localhost"),
        m_config_port(6379)
{}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
redis_db::~redis_db(void)
{
        if(m_ctx)
        {
                redisFree(m_ctx);
                m_ctx = NULL;
        }
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t redis_db::reconnect(void)
{
        // -------------------------------------------------
        // connect to db
        // -------------------------------------------------
        // 0.2 seconds
        // TODO -make configurable...
        struct timeval timeout = { 0, 200000 };
        //NDBG_PRINT("connect to: %s:%d\n", m_config_host.c_str(), m_config_port);
        m_ctx = redisConnectWithTimeout(m_config_host.c_str(), m_config_port, timeout);
        if(!m_ctx)
        {
                //NDBG_PRINT("connection error: can't allocate redis context\n");
                WAFLZ_PERROR(m_err_msg, "can't allocate redis context");
                return WAFLZ_STATUS_ERROR;
        }
        if((m_ctx->err))
        {
                //NDBG_PRINT("Connection error: %s\n", c->errstr);
                WAFLZ_PERROR(m_err_msg, "connection error: %s", m_ctx->errstr);
                if(m_ctx) { redisFree(m_ctx); m_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t redis_db::init(void)
{
        // -------------------------------------------------
        // connect to db
        // -------------------------------------------------
        int32_t l_s;
        l_s = reconnect();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // ping server
        // -------------------------------------------------
        redisReply *l_r = NULL;
        l_r = (redisReply *)redisCommand(m_ctx, "PING");
        if(!l_r)
        {
                WAFLZ_PERROR(m_err_msg, "pinging redis");
                if(m_ctx) { redisFree(m_ctx); m_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        //NDBG_PRINT("PING: %s\n", l_r->str);
        if(strncasecmp(l_r->str, "PONG", strlen("PONG")) != 0)
        {
                WAFLZ_PERROR(m_err_msg, "pinging redis");
                if(m_ctx) { redisFree(m_ctx); m_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if(l_r) { freeReplyObject(l_r); l_r = NULL; }
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t redis_db::increment_key(int64_t &ao_result,
                                const char *a_key,
                                uint32_t a_expires_ms)
{
        if(!m_init ||
           !m_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // psuedo code:
        //   SETNX KEY "0"
        //   if was set:
        //     EXPIRE KEY SECONDS
        //   INCR KEY
        //   save value
        // -------------------------------------------------
        //NDBG_PRINT("INCR: %s expires: %u\n", a_key, a_expires_ms/1000);
        redisReply *l_r = NULL;
        l_r = (redisReply *)redisCommand(m_ctx, "SETNX %b %b", a_key, strlen(a_key), "0", strlen("0"));
        if(!l_r)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -check for errors???
        if(l_r->integer == 1)
        {
                //NDBG_PRINT("set expires...\n");
                if(l_r) { freeReplyObject(l_r); l_r = NULL; }
                uint32_t l_expire_s = a_expires_ms/1000;
                char l_buf[16];
                snprintf(l_buf, 16, "%d", l_expire_s);
                l_r = (redisReply *)redisCommand(m_ctx, "EXPIRE %b %b", a_key, strlen(a_key), l_buf, strlen(l_buf));
                if(!l_r)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        if(l_r) { freeReplyObject(l_r); l_r = NULL; }
        l_r = (redisReply *)redisCommand(m_ctx, "INCR %b", a_key, strlen(a_key));
        if(!l_r)
        {
                return WAFLZ_STATUS_ERROR;
        }
        //NDBG_PRINT("l_r->integer: %lld\n", l_r->integer);
        ao_result = l_r->integer;
        if(l_r) { freeReplyObject(l_r); l_r = NULL; }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t redis_db::get_key(int64_t &ao_val, const char *a_key, uint32_t a_key_len)
{
        if(!m_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        ao_val = 0;
        redisReply *l_r = NULL;
        //NDBG_PRINT("GET: %s\n", a_key);
        l_r = (redisReply *)redisCommand(m_ctx, "GET %b", a_key, strlen(a_key));
        if(!l_r ||
           !l_r->str)
        {
                if(l_r) { freeReplyObject(l_r); l_r = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        ao_val = strtoull(l_r->str, NULL, 10);
        if(l_r) { freeReplyObject(l_r); l_r = NULL; }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t redis_db::print_all_keys(void)
{
        // TODO
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t redis_db::set_opt(uint32_t a_opt, const void *a_buf, uint32_t a_len)
{
        switch(a_opt)
        {
        case OPT_REDIS_HOST:
        {
                m_config_host.assign((char *)a_buf, a_len);
                break;
        }
        case OPT_REDIS_PORT:
        {
                m_config_port = a_len;
                break;
        }
        default:
        {
                //NDBG_PRINT("Error unsupported option: %d\n", a_opt);
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t redis_db::get_opt(uint32_t a_opt, void **a_buf, uint32_t *a_len)
{
        switch(a_opt)
        {
        default:
        {
                //NDBG_PRINT("Error unsupported option: %d\n", a_opt);
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
}
