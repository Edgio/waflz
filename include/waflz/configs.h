//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    configs.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    04/15/2016
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
#ifndef _CONFIGS_H
#define _CONFIGS_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/challenge.h"
#if defined(__APPLE__) || defined(__darwin__)
    #include <unordered_map>
    #include <memory>
#else
    #include <tr1/unordered_map>
    #include <tr1/memory>
#endif
namespace ns_waflz
{
//: ----------------------------------------------------------------------------
//: fwd Decl's
//: ----------------------------------------------------------------------------
class config;
class kv_db;
//: ----------------------------------------------------------------------------
//: config
//: ----------------------------------------------------------------------------
class configs
{
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
#if defined(__APPLE__) || defined(__darwin__)
        typedef std::unordered_map <uint64_t, config*> cust_id_config_map_t;
#else
        typedef std::tr1::unordered_map <uint64_t, config*> cust_id_config_map_t;
#endif
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        configs(kv_db &a_kv_db, challenge& a_challenge, bool a_case_insensitive_headers = false);
        ~configs();
        // load config...
        int32_t load_dir(const char *a_config_dir_path, uint32_t a_config_dir_path_len);
        int32_t load_file(const char *a_file_path, uint32_t a_file_path_len);
        int32_t load(const char *a_buf, uint32_t a_buf_len);
        //: ------------------------------------------------
        //:               G E T T E R S
        //: ------------------------------------------------
        //: ------------------------------------------------
        //: \details Get last error message string
        //: \return  last error message (in buffer)
        //: ------------------------------------------------
        const char *get_err_msg(void)
        {
                return m_err_msg;
        }
        int32_t get_first_id(uint64_t &ao_id);
        int32_t get_config(config** ao_coord, uint64_t a_cust_id);
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // disallow copy/assign
        configs(const configs &);
        configs& operator=(const configs &);
        int32_t load(void *a_js);
        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        bool m_init;
        char m_err_msg[WAFLZ_ERR_LEN];
        cust_id_config_map_t m_cust_id_config_map;
        kv_db &m_db;
        challenge& m_challenge;
        // -------------------------------------------------
        // TODO TEMPORARY HACK to support case insensitive
        // comparisons -need new operators perhaps
        // -------------------------------------------------
        bool m_lowercase_headers;
};
}
#endif
