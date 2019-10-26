//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    instances.cc
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
//: Includes
//: ----------------------------------------------------------------------------
#include "profile.pb.h"
#include "waflz/instances.h"
#include "waflz/instance.h"
#include "waflz/profile.h"
#include "waflz/engine.h"
#include "support/file_util.h"
#include "support/ndebug.h"
#include "support/time_util.h"
#include "rapidjson/document.h"
#include "rapidjson/error/error.h"
#include "rapidjson/error/en.h"
#include <dirent.h>
#include <errno.h>
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#ifndef SET_INSTANCES_CB
#define SET_INSTANCES_CB(_cb, _a_cb) do { \
        for(cust_id_coordinator_map_t::iterator _i_m = m_cust_id_coordinator_map.begin(); \
            _i_m != m_cust_id_coordinator_map.end(); \
            ++_i_m) { \
                if(_i_m->second) { \
                        _i_m->second->_cb(_a_cb); \
                } \
        } \
} while(0)
#endif
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
instances::instances(engine &a_engine,
                     bool a_enable_locking):
        m_err_msg(),
        m_engine(a_engine),
        m_id_instance_map(),
        m_mutex(),
        m_enable_locking(a_enable_locking)
{
        // Initialize the mutex
        if(m_enable_locking)
        {
                pthread_mutex_init(&m_mutex, NULL);
        }
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
instances::~instances()
{
        for (id_instance_map_t::iterator it = m_id_instance_map.begin();
             it != m_id_instance_map.end();
             ++it)
        {
                delete it->second;
                it->second = NULL;
        }
        if(m_enable_locking)
        {
                pthread_mutex_destroy(&m_mutex);
        }
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t instances::load(instance **ao_instance, void *a_js, bool a_update)
{
        if(!a_js)
        {
                WAFLZ_PERROR(m_err_msg, "a_js == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // load
        // -------------------------------------------------
        instance *l_instance = new instance(m_engine);
        int32_t l_s;
        l_s = l_instance->load(a_js);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_AERROR(m_err_msg, "%s", l_instance->get_err_msg());
                if(l_instance) { delete l_instance; l_instance = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_id = l_instance->get_id();
        // -------------------------------------------------
        // check for exist in map
        // -------------------------------------------------
        id_instance_map_t::iterator i_instance;
        i_instance = m_id_instance_map.find(l_id);
        // -------------------------------------------------
        // found existing instance
        // -------------------------------------------------
        if((i_instance != m_id_instance_map.end()) &&
           (i_instance->second != NULL))
        {
                const waflz_pb::instance* l_new_pb = l_instance->get_pb();
                const waflz_pb::instance* l_old_pb = i_instance->second->get_pb();
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
                                //TRC_DEBUG("config is already latest. not performing update");
                                *ao_instance = i_instance->second;
                                // Delete the newly created instance
                                delete l_instance;
                                l_instance = NULL;
                                return WAFLZ_STATUS_OK;
                        }
                }
                delete i_instance->second;
                i_instance->second = NULL;
                i_instance->second = l_instance;
                *ao_instance = l_instance;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // if update
        // -------------------------------------------------
        if(a_update)
        {
                // -----------------------------------------
                // skip updating instances that haven't
                // already been loaded.
                // -----------------------------------------
                //WAFLZ_PERROR(m_err_msg,
                //             "instance_id: '%s' is not currently used -cannot be updated",
                //             l_id.c_str());
                if(l_instance)
                {
                        delete l_instance;
                        l_instance = NULL;
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // add to map
        // -------------------------------------------------
        m_id_instance_map[l_id] = l_instance;
        *ao_instance = l_instance;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t instances::load(instance **ao_instance, const char *a_buf, uint32_t a_buf_len, bool a_update)
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
        // -------------------------------------------------
        // lock
        // -------------------------------------------------
        if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if(l_js->IsObject())
        {
                int32_t l_s;
                l_s = load(ao_instance, (void *)l_js, a_update);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_js) { delete l_js; l_js = NULL; }
                        if(m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // array
        // -------------------------------------------------
        else if(l_js->IsArray())
        {
                for(uint32_t i_e = 0; i_e < l_js->Size(); ++i_e)
                {
                        rapidjson::Value &l_e = (*l_js)[i_e];
                        int32_t l_s;
                        l_s = load(ao_instance, (void *)&l_e, a_update);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                if(l_js) { delete l_js; l_js = NULL; }
                                if(m_enable_locking)
                                {
                                        pthread_mutex_unlock(&m_mutex);
                                }
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        if(l_js) { delete l_js; l_js = NULL; }
        if(m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t instances::load_file(instance **ao_instance,
                             const char *a_file_path,
                             uint32_t a_file_path_len,
                             bool a_update)
{
        int32_t l_s;
        char *l_buf = NULL;
        uint32_t l_buf_len;
        l_s = ns_waflz::read_file(a_file_path, &l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, " :read_file[%s]: %s",
                             a_file_path,
                             ns_waflz::get_err_msg());
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return WAFLZ_STATUS_ERROR;
        }
        l_s = load(ao_instance, l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_AERROR(m_err_msg, " :file[%s]", a_file_path);
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
int32_t instances::load_dir(const char *a_dir_path,
                            uint32_t a_dir_path_len,
                            bool a_update)
{
        // TODO log?
        //TRACE("Loading waf configs from: '%s'", a_config_dir_str);
        // -----------------------------------------------------------
        // this function should look through the given directory and
        // look for all ddos.json files, open them and call
        // load_file() on it
        // -----------------------------------------------------------
        class is_conf_file
        {
        public:
                static int compare(const struct dirent* a_dirent)
                {
                        //NDBG_PRINT("Looking at file: '%s'\n", a_dirent->d_name);
                        switch (a_dirent->d_name[0])
                        {
                        case 'a' ... 'z':
                        case 'A' ... 'Z':
                        case '0' ... '9':
                        case '_':
                        {
                                //NDBG_PRINT("Looking at file: '%s'\n", a_dirent->d_name);
                                // valid path name to consider
                                const char* l_found = NULL;
                                l_found = ::strcasestr(a_dirent->d_name, ".waf.json");
                                // look for the .conf suffix
                                if (l_found == NULL)
                                {
                                        // not a .ddos.json file
                                        //TRACE("Failed to find .ddos.json suffix");
                                        goto done;
                                }
                                //if (::strlen(l_found) != 10)
                                //{
                                //        // failed to find .conf right at the end
                                //        //TRACE("found in the wrong place. %zu", ::strlen(l_found));
                                //        goto done;
                                //}
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
        l_num_files = ::scandir(a_dir_path,
                                &l_conf_list,
                                is_conf_file::compare,
                                alphasort);
        if(l_num_files < 0)
        {
                // failed to build the list of directory entries
                WAFLZ_PERROR(m_err_msg, "Failed to load waf configs. Reason: failed to scan profile directory: %s: %s",
                             a_dir_path,
                             (errno == 0 ? "unknown" : strerror(errno)));
                return WAFLZ_STATUS_ERROR;
        }
        // -----------------------------------------------------------
        // we have a list of .ddos.conf files in the directory
        // -----------------------------------------------------------
        for (int i_f = 0; i_f < l_num_files; ++i_f)
        {
                std::string l_full_path(a_dir_path);
                l_full_path.append("/");
                l_full_path.append(l_conf_list[i_f]->d_name);
                int32_t l_s;
                instance *l_instance = NULL;
                l_s = load_file(&l_instance,
                                l_full_path.c_str(),
                                l_full_path.length(),
                                a_update);
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
int32_t instances::process(waflz_pb::enforcement **ao_enf,
                           waflz_pb::event **ao_audit_event,
                           waflz_pb::event **ao_prod_event,
                           void *a_ctx,
                           const std::string &a_id,
                           part_mk_t a_part_mk,
                           rqst_ctx **ao_rqst_ctx)
{
        if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // get instance for id
        // -------------------------------------------------
        ns_waflz::instance *l_instance = NULL;
        l_instance = get_instance(a_id);
        if(!l_instance)
        {
                if(m_enable_locking)
                {
                        pthread_mutex_unlock(&m_mutex);
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        const waflz_pb::enforcement *l_enf = NULL;
        int32_t l_s;
        l_s = l_instance->process(&l_enf, ao_audit_event, ao_prod_event, a_ctx, a_part_mk, ao_rqst_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(m_enable_locking)
                {
                        pthread_mutex_unlock(&m_mutex);
                }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create enforcement copy...
        // -------------------------------------------------
        if(l_enf)
        {
                *ao_enf = new waflz_pb::enforcement();
                (*ao_enf)->CopyFrom(*l_enf);
        }
        if(m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
instance *instances::get_instance(const std::string &a_id)
{
        id_instance_map_t::iterator i_i;
        i_i = m_id_instance_map.find(a_id);
        if (i_i != m_id_instance_map.end())
        {
                return i_i->second;
        }
        return NULL;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
void instances::get_first_id(std::string &ao_id)
{
        if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        ao_id.clear();
        if(m_id_instance_map.size())
        {
                ao_id = m_id_instance_map.begin()->first;
        }
        if(m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
void instances::get_rand_id(std::string &ao_id)
{
        if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        ao_id.clear();
        uint32_t l_len = (uint32_t)m_id_instance_map.size();
        uint32_t l_idx = 0;
        l_idx = ((uint32_t)rand()) % (l_len + 1);
        id_instance_map_t::const_iterator i_i = m_id_instance_map.begin();
        std::advance(i_i, l_idx);
        ao_id = i_i->first;
        if(m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
bool instances::id_exists(bool& ao_audit, bool &ao_prod, const std::string& a_id)
{
        ao_audit = false;
        ao_prod = false;
        bool l_ret = false;
        if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // find id...
        // -------------------------------------------------
        id_instance_map_t::iterator i_i;
        i_i = m_id_instance_map.find(a_id);
        if (i_i != m_id_instance_map.end())
        {
                instance* l_i = i_i->second;
                // -----------------------------------------
                // set if has audit/prod profiles
                // -----------------------------------------
                if(l_i)
                {
                        if(l_i->get_audit_profile())
                        {
                                ao_audit = true;
                        }
                        if(l_i->get_prod_profile())
                        {
                                ao_audit = true;
                        }
                }
                l_ret = true;
        }
        if(m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return l_ret;
}
}
