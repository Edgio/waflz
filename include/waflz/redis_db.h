//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    redis_db.h
//: \details: redis db kv header for waflz
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
#ifndef _REDIS_DB_H_
#define _REDIS_DB_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
#include "waflz/kv_db.h"
#include "waflz/def.h"
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
struct redisContext;
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: kycb_db
//: ----------------------------------------------------------------------------
class redis_db: public kv_db {
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
        typedef enum opt_enum
        {
                OPT_REDIS_HOST = 0,
                OPT_REDIS_PORT = 1,
                OPT_KYCB_SENTINEL = 999
        } opt_t;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        redis_db(void);
        ~redis_db(void);
        int32_t init(void);
        //: ------------------------------------------------
        //:                  D B   O P S
        //: ------------------------------------------------
        int32_t increment_key(int64_t &ao_result,
                              const char *a_key,
                              uint32_t a_expires_ms);
        int32_t get_key(int64_t &ao_val, const char *a_key, uint32_t a_key_len);
        int32_t print_all_keys(void);
        int32_t set_opt(uint32_t a_opt, const void *a_buf, uint32_t a_len);
        int32_t get_opt(uint32_t a_opt, void **a_buf, uint32_t *a_len);
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        redis_db(const redis_db &);
        redis_db& operator=(const redis_db &);
        int32_t reconnect(void);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        redisContext *m_ctx;
        // -------------------------------------------------
        // config
        // -------------------------------------------------
        std::string m_config_host;
        uint16_t m_config_port;
};
}
#endif
