//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    enforcers.cc
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
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "support/time_util.h"
#include "support/file_util.h"
#include "support/string_util.h"
#include "support/trace_internal.h"
#include "support/ndebug.h"
#include "waflz/limit/configs.h"
#include "waflz/limit/config.h"
#include "waflz/db/kycb_db.h"
#include "rapidjson/document.h"
#include "rapidjson/error/error.h"
#include "rapidjson/error/en.h"
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define CONFIG_RL_DATE_FORMAT "%Y-%m-%dT%H:%M:%S%Z"
namespace ns_waflz {
#if 0
//: ----------------------------------------------------------------------------
//: obj type utils
//: ----------------------------------------------------------------------------
#define RL_OBJ_TYPE_COORDINATOR_STR "ddos-coordinator"
#define RL_OBJ_TYPE_ENFORCER_STR "ddos-enforcer"
#define RL_OBJ_TYPE_ENFORCEMENT_STR "ddos-enforcement"
//: ----------------------------------------------------------------------------
//: rl type enum
//: ----------------------------------------------------------------------------
typedef enum {
        LIMIT_OBJ_TYPE_NONE = 0,
        LIMIT_OBJ_TYPE_CONFIG,
        LIMIT_OBJ_TYPE_ENFCR
} limit_obj_type_t;
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
limit_obj_type_t rl_obj_get_type(const char *a_buf)
{
        // TODO caseless???
        if(strncmp(RL_OBJ_TYPE_COORDINATOR_STR, a_buf, sizeof(RL_OBJ_TYPE_COORDINATOR_STR)) == 0)
        {
                return LIMIT_OBJ_TYPE_CONFIG;
        }
        else if(strncmp(RL_OBJ_TYPE_ENFORCER_STR, a_buf, sizeof(RL_OBJ_TYPE_ENFORCER_STR)) == 0)
        {
                return LIMIT_OBJ_TYPE_ENFCR;
        }
        else if(strncmp(RL_OBJ_TYPE_ENFORCEMENT_STR, a_buf, sizeof(RL_OBJ_TYPE_ENFORCEMENT_STR)) == 0)
        {
                return LIMIT_OBJ_TYPE_ENFCR;
        }
        return LIMIT_OBJ_TYPE_NONE;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t rl_obj_get_type(limit_obj_type_t &ao_obj_type,
                        const char *a_buf,
                        uint32_t a_buf_len)
{
        // init
        ao_obj_type = LIMIT_OBJ_TYPE_NONE;
        // Parse
        rapidjson::Document *l_doc = new rapidjson::Document();
        l_doc->Parse(a_buf, a_buf_len);
        // get obj type
        if(l_doc->IsObject())
        {
                // Grab type field.
                if(l_doc->HasMember("type") &&
                   (*l_doc)["type"].IsString())
                {
                        const char *l_type = (*l_doc)["type"].GetString();
                        ao_obj_type = rl_obj_get_type(l_type);
                }
        }
        else if(l_doc->IsArray())
        {
                // Grab type from first object...
                if(l_doc->Size() &&
                   (*l_doc)[0].HasMember("type") &&
                   (*l_doc)[0]["type"].IsString())
                {
                        const char *l_type = (*l_doc)[0]["type"].GetString();
                        ao_obj_type = rl_obj_get_type(l_type);
                }
        }
        else
        {
                RATLZ_PERROR(g_rl_obj_get_type_err_msg, "error json is not object or array");
                if(l_doc) { delete l_doc; l_doc = NULL;}
                return STATUS_ERROR;
        }
        if(ao_obj_type == RL_OBJ_TYPE_NONE)
        {
                RATLZ_PERROR(g_rl_obj_get_type_err_msg, "error json has no type field or not ddos-enforcer or ddos-coordinator type");
                if(l_doc) { delete l_doc; l_doc = NULL;}
                return STATUS_ERROR;
        }
        if(l_doc) { delete l_doc; l_doc = NULL;}
        return WAFLZ_STATUS_OK;
}
#endif
//: ----------------------------------------------------------------------------
//: \details Initialize a ddos config using the provided
//:          parameter to load in all the configurations and
//:          initialize the customer-id based structures to track limits
//: ----------------------------------------------------------------------------
configs::configs(kv_db &a_kv_db, challenge& a_challenge, bool a_case_insensitive_headers):
        m_init(false),
        m_err_msg(),
        m_cust_id_config_map(),
        m_db(a_kv_db),
        m_challenge(a_challenge),
        m_lowercase_headers(a_case_insensitive_headers)
{
}
//: ----------------------------------------------------------------------------
//: \details dtor
//: ----------------------------------------------------------------------------
configs::~configs()
{
        for (cust_id_config_map_t::iterator it = m_cust_id_config_map.begin();
             it != m_cust_id_config_map.end();
             ++it)
        {
                delete it->second;
                it->second = NULL;
        }
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t configs::load(void *a_js)
{
        if(!a_js)
        {
                WAFLZ_PERROR(m_err_msg, "a_js == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        const rapidjson::Value &l_js = *((rapidjson::Value *)a_js);
        if(!l_js.IsObject())
        {
                return WAFLZ_STATUS_ERROR;
        }
#if 0
        // -------------------------------------------------
        // check type
        // -------------------------------------------------
        rl_obj_type_t l_t = rl_obj_type_t::RL_OBJ_TYPE_NONE;
        const char *l_str = "";
        if(l_js.HasMember("type") &&
           l_js["type"].IsString())
        {
                l_str = l_js["type"].GetString();
                l_t = rl_obj_get_type(l_str);
        }
        if(l_t == rl_obj_type_t::RL_OBJ_TYPE_NONE)
        {
                RATLZ_PERROR(m_err_msg, "unrecognized type string: %s", l_str);
                return STATUS_ERROR;
        }
#endif
        // -------------------------------------------------
        // get id
        // -------------------------------------------------
        uint64_t l_cust_id = 0;
        if(l_js.HasMember("customer_id") &&
           l_js["customer_id"].IsString())
        {
                const char *l_str = l_js["customer_id"].GetString();
                TRC_ALL("customer_id: %s\n", l_str);
                int32_t l_s;
                l_s = convert_hex_to_uint(l_cust_id, l_str);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing convert_hex_to_uint");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        TRC_ALL("customer_id(int): %lu\n", l_cust_id);
        // -------------------------------------------------
        // find in map
        // -------------------------------------------------
        cust_id_config_map_t::iterator i_cust;
        i_cust = m_cust_id_config_map.find(l_cust_id);
#if 0
        // -------------------------------------------------
        // handle enforcer
        // -------------------------------------------------
        if(l_t == rl_obj_type_t::RL_OBJ_TYPE_ENFORCER)
        {
                if(i_cust == m_cust_id_coordinator_map.end())
                {
                        RATLZ_PERROR(m_err_msg, "can't load enforcers w/o coordinator for id: %lu",
                                     l_cust_id);
                        return STATUS_ERROR;
                }
                if(!i_cust->second)
                {
                        RATLZ_PERROR(m_err_msg, "can't load enforcers for coordinator for id: %lu -coordinator NULL",
                                     l_cust_id);
                        return STATUS_ERROR;
                }
                int32_t l_s;
                l_s = (i_cust->second)->merge((void *)&l_js);
                if(l_s != STATUS_OK)
                {
                        RATLZ_PERROR(m_err_msg, "performing merge for id: %lu. Reason: %s",
                                     l_cust_id,
                                     (i_cust->second)->get_err_msg());
                        return STATUS_ERROR;
                }
                return STATUS_OK;
        }
#endif
        config *l_c = new config(m_db, m_challenge, m_lowercase_headers);
        int32_t l_s;
        // -------------------------------------------------
        // load
        // -------------------------------------------------
        l_s = l_c->load((void *)&l_js);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing load. Reason: %s",
                             l_c->get_err_msg());
                if(l_c) { delete l_c; l_c = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // add to map...
        // -------------------------------------------------
        if(i_cust == m_cust_id_config_map.end())
        {
                m_cust_id_config_map[l_cust_id] = l_c;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // blanked config???
        // -------------------------------------------------
        if(!i_cust->second)
        {
                i_cust->second = l_c;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check modified date
        // skip if loaded is older than current
        // -------------------------------------------------
        const std::string& l_lmd_cur = i_cust->second->get_last_modified_date();
        const std::string& l_lmd_new = l_c->get_last_modified_date();
        if(!l_lmd_cur.empty() &&
           !l_lmd_new.empty())
        {
                uint64_t l_loaded_epoch = get_epoch_seconds(l_lmd_cur.c_str(), CONFIG_RL_DATE_FORMAT);
                uint64_t l_config_epoch = get_epoch_seconds(l_lmd_new.c_str(), CONFIG_RL_DATE_FORMAT);
                if(l_loaded_epoch >= l_config_epoch)
                {
                        TRC_DEBUG("config is already latest. not performing update");
                        if(l_c) { delete l_c; l_c = NULL; }
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // delete old cust config
        // -------------------------------------------------
        delete i_cust->second;
        i_cust->second = NULL;
        // -------------------------------------------------
        // set new value
        // -------------------------------------------------
        i_cust->second = l_c;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t configs::load(const char *a_buf, uint32_t a_buf_len)
{
        // ---------------------------------------
        // parse
        // ---------------------------------------
        rapidjson::Document *l_js = new rapidjson::Document();
        rapidjson::ParseResult l_ok;
        l_ok = l_js->Parse(a_buf, a_buf_len);
        if (!l_ok)
        {
                WAFLZ_PERROR(m_err_msg, "JSON parse error: %s (%d)\n",
                             rapidjson::GetParseError_En(l_ok.Code()), (int)l_ok.Offset());
                if(l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_js->IsObject() &&
           !l_js->IsArray())
        {
                WAFLZ_PERROR(m_err_msg, "error parsing json");
                if(l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // ---------------------------------------
        // object
        // ---------------------------------------
        if(l_js->IsObject())
        {
                int32_t l_s;
                l_s = load((void *)l_js);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_js) { delete l_js; l_js = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // ---------------------------------------
        // array
        // ---------------------------------------
        else if(l_js->IsArray())
        {
                for(uint32_t i_e = 0; i_e < l_js->Size(); ++i_e)
                {
                        rapidjson::Value &l_e = (*l_js)[i_e];
                        int32_t l_s;
                        l_s = load((void *)&l_e);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                if(l_js) { delete l_js; l_js = NULL; }
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        if(l_js) { delete l_js; l_js = NULL; }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t configs::load_dir(const char *a_config_dir_str,
                          uint32_t a_config_dir_str_len)
{
        // TODO log?
        //TRACE("Loading ddos enforcer configs from: '%s'", a_config_dir_str);
        // -----------------------------------------------------------
        // this function should look through the given directory and
        // look for all ddos.json files, open them and call
        // load_configfile() on it
        // -----------------------------------------------------------
        class is_conf_file
        {
        public:
                static int compare(const struct dirent* a_dirent)
                {
                        //TRACE("Looking at file: '%s'", a_dirent->d_name);
                        switch (a_dirent->d_name[0])
                        {
                        case 'a' ... 'z':
                        case 'A' ... 'Z':
                        case '0' ... '9':
                        case '_':
                        {
                                // valid path name to consider
                                const char* l_found = NULL;
                                l_found = ::strcasestr(a_dirent->d_name, ".ddos.json");
                                // look for the .conf suffix
                                if (l_found == NULL)
                                {
                                        // not a .ddos.json file
                                        //TRACE("Failed to find .ddos.json suffix");
                                        goto done;
                                }
                                if (::strlen(l_found) != 10)
                                {
                                        // failed to find .conf right at the end
                                        //TRACE("found in the wrong place. %zu", ::strlen(l_found));
                                        goto done;
                                }
                                // we want this file
                                return 1;
                                break;
                        }
                        default:
                                //TRACE("Found invalid first char: '%c'", a_dirent->d_name[0]);
                                goto done;
                        }
                done:
                        return 0;
                }
        };
        // -----------------------------------------------------------
        // scandir
        // -----------------------------------------------------------
        struct dirent** l_conf_list;
        int l_num_files = -1;
        l_num_files = ::scandir(a_config_dir_str,
                                &l_conf_list,
                                is_conf_file::compare,
                                alphasort);
        if(l_num_files < 0)
        {
                // failed to build the list of directory entries
                WAFLZ_PERROR(m_err_msg, "Failed to load rl config configs. Reason: failed to scan profile directory: %s: %s",
                             a_config_dir_str,
                             (errno == 0 ? "unknown" : strerror(errno)));
                return WAFLZ_STATUS_ERROR;
        }
        // -----------------------------------------------------------
        // we have a list of .ddos.conf files in the directory
        // -----------------------------------------------------------
        for (int i_f = 0; i_f < l_num_files; ++i_f)
        {
                // for each file
                // TODO log?
                //TRACE("Found ddos config file: '%s'", l_conf_list[i_f]->d_name);
                std::string l_full_path(a_config_dir_str);
                l_full_path.append("/");
                l_full_path.append(l_conf_list[i_f]->d_name);
                int32_t l_s;
                l_s = load_file(l_full_path.c_str(),l_full_path.length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // failed to load a config file
                        for (int i_f2 = 0; i_f2 < l_num_files; ++i_f2) free(l_conf_list[i_f2]);
                        free(l_conf_list);
                        return WAFLZ_STATUS_ERROR;
                }
        }
        for (int i_f = 0; i_f < l_num_files; ++i_f) free(l_conf_list[i_f]);
        free(l_conf_list);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t configs::load_file(const char *a_file_path,
                                       uint32_t a_file_path_len)
{
        int32_t l_s;
        char *l_buf = NULL;
        uint32_t l_buf_len;
        l_s = read_file(a_file_path, &l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing read_file: %s. Reason: %s",
                             a_file_path,
                             get_err_msg());
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return WAFLZ_STATUS_ERROR;
        }
        l_s = load(l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return WAFLZ_STATUS_ERROR;
        }
        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t configs::get_first_id(uint64_t &ao_id)
{
        if(m_cust_id_config_map.empty())
        {
                WAFLZ_PERROR(m_err_msg, "config map empty");
                return WAFLZ_STATUS_ERROR;
        }
        ao_id = m_cust_id_config_map.begin()->first;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t configs::get_config(config** ao_config, uint64_t a_cust_id)
{
        cust_id_config_map_t::iterator i_e;
        i_e = m_cust_id_config_map.find(a_cust_id);
        if(i_e == m_cust_id_config_map.end())
        {
                return WAFLZ_STATUS_ERROR;
        }
        if(!i_e->second)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_config = i_e->second;
        return WAFLZ_STATUS_OK;
}
}
