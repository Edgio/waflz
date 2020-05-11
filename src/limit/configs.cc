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
#include "support/ndebug.h"
#include "waflz/configs.h"
#include "waflz/config.h"
#include "waflz/kycb_db.h"
#include "rapidjson/document.h"
#include "rapidjson/error/error.h"
#include "rapidjson/error/en.h"
#include <errno.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: obj type utils
//: ----------------------------------------------------------------------------
#define LIMIT_OBJ_CONFIG_STR "CONFIG"
#define LIMIT_OBJ_COORDINATOR_STR "ddos-coordinator"
#define LIMIT_OBJ_ENFORCER_STR "ddos-enforcer"
#define LIMIT_OBJ_ENFORCEMENT_STR "ddos-enforcement"
//: ----------------------------------------------------------------------------
//: rl type enum
//: ----------------------------------------------------------------------------
typedef enum {
        _LIMIT_OBJ_NONE = 0,
        _LIMIT_OBJ_CONFIG,
} limit_obj_t;
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static limit_obj_t limit_obj_get_type(const char *a_buf)
{
        if(strncasecmp(LIMIT_OBJ_CONFIG_STR, a_buf, sizeof(LIMIT_OBJ_CONFIG_STR)) == 0)
        {
                return _LIMIT_OBJ_CONFIG;
        }
        // TODO caseless???
        if(strncmp(LIMIT_OBJ_COORDINATOR_STR, a_buf, sizeof(LIMIT_OBJ_COORDINATOR_STR)) == 0)
        {
                return _LIMIT_OBJ_CONFIG;
        }
        return _LIMIT_OBJ_NONE;
}
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
        // -------------------------------------------------
        // check string types
        // -------------------------------------------------
        limit_obj_t l_t = _LIMIT_OBJ_NONE;
        if(l_js.HasMember("type") &&
           l_js["type"].IsString())
        {
                const char *l_str = "";
                l_str = l_js["type"].GetString();
                l_t = limit_obj_get_type(l_str);
                if(l_t == _LIMIT_OBJ_NONE)
                {
                        WAFLZ_PERROR(m_err_msg, "unrecognized type string: %s", l_str);
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // get id
        // -------------------------------------------------
        uint64_t l_cust_id = 0;
        if(l_js.HasMember("customer_id") &&
           l_js["customer_id"].IsString())
        {
                const char *l_str = l_js["customer_id"].GetString();
                //TRC_ALL("customer_id: %s\n", l_str);
                int32_t l_s;
                l_s = convert_hex_to_uint(l_cust_id, l_str);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing convert_hex_to_uint");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        //TRC_ALL("customer_id(int): %lu\n", l_cust_id);
        // -------------------------------------------------
        // find in map
        // -------------------------------------------------
        config *l_c = new config(m_db, m_challenge, m_lowercase_headers);
        int32_t l_s;
        // -------------------------------------------------
        // load
        // -------------------------------------------------
        l_s = l_c->load((void *)&l_js);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s",
                             l_c->get_err_msg());
                if(l_c) { delete l_c; l_c = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // add to map...
        // -------------------------------------------------
        cust_id_config_map_t::iterator i_cust;
        i_cust = m_cust_id_config_map.find(l_cust_id);
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
                uint64_t l_loaded_epoch = get_epoch_seconds(l_lmd_cur.c_str(), CONFIG_DATE_FORMAT);
                uint64_t l_config_epoch = get_epoch_seconds(l_lmd_new.c_str(), CONFIG_DATE_FORMAT);
                if(l_loaded_epoch >= l_config_epoch)
                {
                        //TRC_DEBUG("config is already latest. not performing update");
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
                WAFLZ_PERROR(m_err_msg, "JSON parse error: %s (%d)",
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
