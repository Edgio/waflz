//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    scopes_configs.cc
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
#include "support/file_util.h"
#include "support/time_util.h"
#include "support/trace_internal.h"
#include "support/string_util.h"
#include "waflz/scopes_configs.h"
#include "waflz/scopes.h"
#include "rapidjson/document.h"
#include "rapidjson/error/error.h"
#include "rapidjson/error/en.h"
#include <dirent.h>
#include "scope.pb.h"

namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
scopes_configs::scopes_configs(engine &a_engine):
		m_cust_id_scopes_map(),
        m_engine(a_engine),
        m_err_msg(),
        m_geoip2_mmdb()
{
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
scopes_configs::~scopes_configs()
{
		for (cust_id_scopes_map_t::iterator  it = m_cust_id_scopes_map.begin();
			 it != m_cust_id_scopes_map.end();
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
int32_t scopes_configs::load_scopes_dir(const char* a_scopes_dir_str, uint32_t a_scopes_dir_str_len)
{
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
        l_num_files = ::scandir(a_scopes_dir_str,
                                &l_conf_list,
                                is_conf_file::compare,
                                alphasort);
        if(l_num_files < 0)
        {
                // failed to build the list of directory entries
                WAFLZ_PERROR(m_err_msg, "Failed to load rl config configs. Reason: failed to scan profile directory: %s: %s",
                             a_scopes_dir_str,
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
                std::string l_full_path(a_scopes_dir_str);
                l_full_path.append("/");
                l_full_path.append(l_conf_list[i_f]->d_name);
                int32_t l_s;
                l_s = load_scopes_file(l_full_path.c_str(),l_full_path.length());
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
int32_t scopes_configs::load_scopes_file(const char* a_scopes_file_path, uint32_t a_scopes_file_path_len)
{
        int32_t l_s;
        char *l_buf = NULL;
        uint32_t l_buf_len;
        l_s = read_file(a_scopes_file_path, &l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing read_file: %s. Reason: %s",
                             a_scopes_file_path,
                             get_err_msg());
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return WAFLZ_STATUS_ERROR;
        }
        l_s = load_scopes(l_buf, l_buf_len);
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
int32_t scopes_configs::load_scopes(const char *a_buf, uint32_t a_buf_len)
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
int32_t scopes_configs::load(void* a_js)
{
        if(!a_js)
        {
                WAFLZ_PERROR(m_err_msg, "a_js == NULL");
                return WAFLZ_STATUS_ERROR;                
        }

        scopes *l_scopes = new scopes(m_engine, *m_geoip2_mmdb);
        int32_t l_s;
        l_s = l_scopes->load_config(a_js);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_AERROR(m_err_msg, "%s", l_scopes->get_err_msg());
                if(l_scopes) { delete l_scopes; l_scopes = NULL;}
                return WAFLZ_STATUS_ERROR;                
        }
        uint64_t l_cust_id = 0;
        std::string& l_id_str = l_scopes->get_id();
        l_s = convert_hex_to_uint(l_cust_id, l_id_str.c_str());
        if(l_s != WAFLZ_STATUS_OK)
        {
        		WAFLZ_PERROR(m_err_msg, "performing convert_hex_to_uint");
        		return WAFLZ_STATUS_ERROR;
        }       
        // -------------------------------------------------
        // check for exist in map
        // -------------------------------------------------
        cust_id_scopes_map_t::iterator i_scopes;
        i_scopes = m_cust_id_scopes_map.find(l_cust_id);
        // -------------------------------------------------
        // found existing instance
        // -------------------------------------------------
        if((i_scopes != m_cust_id_scopes_map.end()) &&
            i_scopes->second != NULL)
        {
                const waflz_pb::scope_config* l_new_pb = l_scopes->get_pb();
                const waflz_pb::scope_config* l_old_pb = i_scopes->second->get_pb();
                if((l_old_pb != NULL) &&
                   (l_new_pb != NULL) &&
                   (l_old_pb->has_last_modified_date()) &&
                   (l_new_pb->has_last_modified_date()))
                {
                        uint64_t l_loaded_epoch = get_epoch_seconds(l_old_pb->last_modified_date().c_str(),
                                                                    CONFIG_DATE_FORMAT);
                        uint64_t l_config_epoch = get_epoch_seconds(l_new_pb->last_modified_date().c_str(),
                                                                    CONFIG_DATE_FORMAT);
                        if(l_loaded_epoch >= l_config_epoch)
                        {
                                TRC_DEBUG("config is already latest. not performing update");
                                // Delete the newly created scope
                                delete l_scopes;
                                l_scopes = NULL;
                                return WAFLZ_STATUS_OK;
                        }
                }
                delete i_scopes->second;
                i_scopes->second = NULL;
                i_scopes->second = l_scopes;
                return WAFLZ_STATUS_OK;                
        }
        //TODO: check if its ok to update instance that
        // has not been loaded before. Introduce a_update 
        // var if it is required
        // -------------------------------------------------
        // add to map
        // -------------------------------------------------
        m_cust_id_scopes_map[l_cust_id] = l_scopes;
		return WAFLZ_STATUS_OK;
}

}