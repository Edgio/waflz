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
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "waflz/scopes_configs.h"
#include "waflz/scopes.h"
#include "waflz/rules.h"
#include "waflz/acl.h"
#include "waflz/trace.h"
#include "rapidjson/document.h"
#include "rapidjson/error/error.h"
#include "rapidjson/error/en.h"
#include "support/file_util.h"
#include "support/time_util.h"
#include "support/ndebug.h"
#include "support/string_util.h"
#include <dirent.h>
#include "scope.pb.h"
#include "limit.pb.h"
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
scopes_configs::scopes_configs(engine &a_engine,
                               kv_db& a_db,
                               challenge& a_challenge,
                               bool a_enable_locking):
        m_cust_id_scopes_map(),
        m_err_msg(),
        m_engine(a_engine),
        m_db(a_db),
        m_mutex(),
        m_enable_locking(a_enable_locking),
        m_conf_dir(),
        m_challenge(a_challenge)
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
scopes_configs::~scopes_configs()
{
        for (cust_id_scopes_map_t::iterator  it = m_cust_id_scopes_map.begin();
             it != m_cust_id_scopes_map.end();
             ++it)
        {
                delete it->second;
                it->second = NULL;
        }
        // destroy mutex
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
int32_t scopes_configs::load_dir(const char* a_dir_path, uint32_t a_dir_path_len)
{
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
                        switch (a_dirent->d_name[0])
                        {
                        case 'a' ... 'z':
                        case 'A' ... 'Z':
                        case '0' ... '9':
                        case '_':
                        {
                                // valid path name to consider
                                const char* l_found = NULL;
                                l_found = ::strcasestr(a_dirent->d_name, ".scopes.json");
                                // look for the .conf suffix
                                if (l_found == NULL)
                                {
                                        // not a .scopes.json file
                                        //NDBG_PRINT("Failed to find .scopes.json suffix\n");
                                        goto done;
                                }
                                if (::strlen(l_found) != 12)
                                {
                                        // failed to find .scopes.json right at the end
                                       // NDBG_PRINT("found in the wrong place. %zu", ::strlen(l_found));
                                        goto done;
                                }
                                // we want this file
                                return 1;
                                break;
                        }
                        default:
                                //NDBG_PRINT("Found invalid first char: '%c'", a_dirent->d_name[0]);
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
                WAFLZ_PERROR(m_err_msg, "Failed to load scope config  Reason: failed to scan profile directory: %s: %s",
                             a_dir_path,
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
                //NDBG_PRINT("Found scope config file: %s", l_conf_list[i_f]->d_name );
                std::string l_full_path(a_dir_path);
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
int32_t scopes_configs::load_file(const char* a_file_path,
                                         uint32_t a_file_path_len)
{
        int32_t l_s;
        char *l_buf = NULL;
        uint32_t l_buf_len;
        l_s = read_file(a_file_path, &l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, ":read_file[%s]: %s",
                             a_file_path,
                             ns_waflz::get_err_msg());
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
int32_t scopes_configs::load(const char *a_buf, uint32_t a_buf_len)
{
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
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
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        if(l_js->IsObject())
        {
                int32_t l_s;
                l_s = load((void *)l_js);
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
                        l_s = load((void *)&l_e);
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
int32_t scopes_configs::load(void* a_js)
{
        if(!a_js)
        {
                WAFLZ_PERROR(m_err_msg, "a_js == NULL");
                return WAFLZ_STATUS_ERROR;                
        }

        scopes *l_scopes = new scopes(m_engine, m_db, m_challenge);
        int32_t l_s;
        l_s = l_scopes->load(a_js, m_conf_dir);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", l_scopes->get_err_msg());
                if(l_scopes) { delete l_scopes; l_scopes = NULL;}
                return WAFLZ_STATUS_ERROR;                
        }
        uint64_t l_cust_id = 0;
        std::string& l_id_str = l_scopes->get_cust_id();
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
        // found existing scope
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
        // -------------------------------------------------
        // add to map
        // -------------------------------------------------
        m_cust_id_scopes_map[l_cust_id] = l_scopes;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes_configs::process(waflz_pb::enforcement **ao_enf,
                                waflz_pb::event **ao_audit_event,
                                waflz_pb::event **ao_prod_event,
                                void *a_ctx,
                                uint64_t a_id,
                                part_mk_t a_part_mk,
                                rqst_ctx **ao_rqst_ctx)
{
        if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // get scopes for id
        // -------------------------------------------------
        ns_waflz::scopes *l_scopes = NULL;
        l_scopes = get_scopes(a_id);
        if(!l_scopes)
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
        l_s = l_scopes->process(&l_enf, ao_audit_event, ao_prod_event, a_ctx, a_part_mk, ao_rqst_ctx);
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
void scopes_configs::get_first_id(uint64_t &ao_id)
{
        if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        ao_id = 0;
        if(m_cust_id_scopes_map.size())
        {
                ao_id = m_cust_id_scopes_map.begin()->first;
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
void scopes_configs::get_rand_id(uint64_t &ao_id)
{
        if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        ao_id = 0;
        uint32_t l_len = (uint32_t)m_cust_id_scopes_map.size();
        uint32_t l_idx = 0;
        l_idx = ((uint32_t)rand()) % (l_len + 1);
        cust_id_scopes_map_t::const_iterator i_i = m_cust_id_scopes_map.begin();
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
bool scopes_configs::id_exists(uint64_t a_id)
{
        bool l_ret = false;
        if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // find id...
        // -------------------------------------------------
        cust_id_scopes_map_t::iterator i_i;
        i_i = m_cust_id_scopes_map.find(a_id);
        if (i_i != m_cust_id_scopes_map.end())
        {
                l_ret = true;
        }
        if(m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return l_ret;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
scopes* scopes_configs::get_scopes(uint64_t a_id)
{
        cust_id_scopes_map_t::iterator i_i;
        i_i = m_cust_id_scopes_map.find(a_id);
        if (i_i != m_cust_id_scopes_map.end())
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
int32_t scopes_configs::generate_alert(waflz_pb::alert** ao_alert,
                                       rqst_ctx* a_ctx,
                                       uint64_t a_cust_id)
{
        waflz_pb::alert* l_at = new waflz_pb::alert();
        // -------------------------------------------------
        // Get the matched limit
        // -------------------------------------------------
        if(a_ctx->m_limit)
        {
                waflz_pb::limit *l_ev_limit = l_at->mutable_limit();
                // TODO -only copy in meta -ie exclude enforcement body info...
                l_ev_limit->CopyFrom(*(a_ctx->m_limit));
                // -----------------------------------------
                // copy in first enf
                // -----------------------------------------
                if(a_ctx->m_limit->has_action())
                {
                        l_at->mutable_action()->CopyFrom(a_ctx->m_limit->action());
                }
        }
        // -------------------------------------------------
        // Get the matched limit
        // -------------------------------------------------
        if(a_ctx->m_limit)
        {
                waflz_pb::limit *l_ev_limit = l_at->mutable_limit();
                l_ev_limit->CopyFrom(*(a_ctx->m_limit));
        }
        // -------------------------------------------------
        // Get request specific info
        // -------------------------------------------------
        if(!a_ctx)
        {
                return WAFLZ_STATUS_OK;
        }
        waflz_pb::request_info *l_request_info = l_at->mutable_req_info();
        // -------------------------------------------------
        // Epoch time
        // -------------------------------------------------
        uint32_t l_now_s = get_time_s();
        uint32_t l_now_ms = get_time_ms();
        waflz_pb::request_info_timespec_t *l_epoch = l_request_info->mutable_epoch_time();
        l_epoch->set_sec(l_now_s);
        l_epoch->set_nsec(l_now_ms);
        // -------------------------------------------------
        // common headers
        // -------------------------------------------------
        //TRC_DEBUG("setting headers\n");
#define _SET_HEADER(_header, _val) do { \
        l_d.m_data = _header; \
        l_d.m_len = sizeof(_header); \
        data_map_t::const_iterator i_h = l_hm.find(l_d); \
        if(i_h != l_hm.end()) \
        { \
                l_headers->set_##_val(i_h->second.m_data, i_h->second.m_len); \
        } \
} while(0)
#define _SET_IF_EXIST_STR(_field, _proto) do { \
        if(a_ctx->_field.m_data && \
           a_ctx->_field.m_len) { \
                l_request_info->set_##_proto(a_ctx->_field.m_data, a_ctx->_field.m_len); \
        } } while(0)
#define _SET_IF_EXIST_INT(_field, _proto) do { \
                l_request_info->set_##_proto(a_ctx->_field); \
        } while(0)
        // -------------------------------------------------
        // headers...
        // -------------------------------------------------
        waflz_pb::request_info::common_header_t* l_headers = l_request_info->mutable_common_header();
        const data_map_t &l_hm = a_ctx->m_header_map;
        data_t l_d;
        _SET_HEADER("Referer", referer);
        _SET_HEADER("User-Agent", user_agent);
        _SET_HEADER("Host", host);
        _SET_HEADER("X-Forwarded-For", x_forwarded_for);
        // -------------------------------------------------
        // others...
        // -------------------------------------------------
        _SET_IF_EXIST_STR(m_src_addr, virt_remote_host);
        _SET_IF_EXIST_STR(m_local_addr, local_addr);
        _SET_IF_EXIST_INT(m_port, server_canonical_port);
        _SET_IF_EXIST_STR(m_uri, orig_url);
        _SET_IF_EXIST_STR(m_url, url);
        _SET_IF_EXIST_STR(m_query_str, query_string);
        _SET_IF_EXIST_STR(m_method, request_method);
        _SET_IF_EXIST_STR(m_req_uuid, req_uuid);
        _SET_IF_EXIST_INT(m_bytes_out, bytes_out);
        _SET_IF_EXIST_INT(m_bytes_in, bytes_in);
        // -------------------------------------------------
        // TODO -apologies for enum casting...
        // -------------------------------------------------
        l_request_info->set_apparent_cache_log_status(static_cast <waflz_pb::request_info::log_status_t>(a_ctx->m_apparent_cache_status));
        // -------------------------------------------------
        // set customer id...
        // -------------------------------------------------
        l_at->mutable_req_info()->set_customer_id(a_cust_id);
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        *ao_alert = l_at;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details check if customer has scopes
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
bool scopes_configs::check_id(uint64_t a_cust_id)
{
        cust_id_scopes_map_t::iterator i_scopes;
        i_scopes = m_cust_id_scopes_map.find(a_cust_id);
        if(i_scopes == m_cust_id_scopes_map.end())
        {
                return false;
        }
        return true;
}
//: ----------------------------------------------------------------------------
//: \details update scopes limit config
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes_configs::load_limit(void* a_js)
{
        int32_t l_s;
        ns_waflz::limit* l_limit = new limit(m_db);
        l_s = l_limit->load(a_js);
         if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "limit loading failed");
                if(l_limit) { delete l_limit;l_limit = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        uint64_t l_id;
        const std::string& l_cust_id = l_limit->get_cust_id();
        l_s = ns_waflz::convert_hex_to_uint(l_id, l_cust_id.c_str());
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg,"conversion to uint failed\n");
                if(l_limit) { delete l_limit;l_limit = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        cust_id_scopes_map_t::iterator i_scopes;
        i_scopes = m_cust_id_scopes_map.find(l_id);
        if(i_scopes == m_cust_id_scopes_map.end())
        {

                WAFLZ_PERROR(m_err_msg, "customer id - %" PRIu64 " not found in the scopes map", l_id);
                if(l_limit) { delete l_limit; l_limit = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        l_s = i_scopes->second->load_limit(l_limit);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", i_scopes->second->get_err_msg());
                if(l_limit) { delete l_limit; l_limit = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details update limit config
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes_configs::load_limit(const char* a_buf, uint32_t a_buf_len)
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
        int32_t l_s;
       if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if(l_js->IsObject())
        {
                l_s = load_limit(l_js);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        if(l_js) { delete l_js; l_js = NULL;}
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
                        l_s = load_limit((void*)&l_e);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                if(m_enable_locking)
                                {
                                        pthread_mutex_unlock(&m_mutex);
                                }
                                if(l_js) { delete l_js; l_js = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        if(l_js) { delete l_js; l_js = NULL;}
        if(m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details update scopes acl config
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes_configs::load_acl(void* a_js)
{
        int32_t l_s;
        ns_waflz::acl* l_acl = new acl();
        l_s = l_acl->load(a_js);
         if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "acl loading failed");
                if(l_acl) { delete l_acl;l_acl = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        uint64_t l_id;
        const std::string& l_cust_id = l_acl->get_cust_id();
        l_s = ns_waflz::convert_hex_to_uint(l_id, l_cust_id.c_str());
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg,"conversion to uint failed\n");
                if(l_acl) { delete l_acl;l_acl = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        cust_id_scopes_map_t::iterator i_scopes;
        i_scopes = m_cust_id_scopes_map.find(l_id);
        if(i_scopes == m_cust_id_scopes_map.end())
        {

                WAFLZ_PERROR(m_err_msg, "customer id - %" PRIu64 " not found in the scopes map", l_id);
                if(l_acl) { delete l_acl; l_acl = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        l_s = i_scopes->second->load_acl(l_acl);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", i_scopes->second->get_err_msg());
                if(l_acl) { delete l_acl; l_acl = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details update acl config
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes_configs::load_acl(const char* a_buf, uint32_t a_buf_len)
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
        int32_t l_s;
       if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if(l_js->IsObject())
        {
                l_s = load_acl(l_js);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        if(l_js) { delete l_js; l_js = NULL;}
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
                        l_s = load_acl((void*)&l_e);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                if(m_enable_locking)
                                {
                                        pthread_mutex_unlock(&m_mutex);
                                }
                                if(l_js) { delete l_js; l_js = NULL;}
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
//: \details update custom rules config
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes_configs::load_rules(void* a_js)
{
        int32_t l_s;
        ns_waflz::rules* l_rules = new rules(m_engine);
        l_s = l_rules->load(a_js);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_rules) { delete l_rules; l_rules = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        uint64_t l_id;
        const std::string& l_cust_id = l_rules->get_cust_id();
        l_s = ns_waflz::convert_hex_to_uint(l_id, l_cust_id.c_str());
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg,"conversion to uint failed\n");
                if(l_rules) { delete l_rules; l_rules = NULL; }
                return WAFLZ_STATUS_ERROR;
        }       
        cust_id_scopes_map_t::iterator i_scopes;
        i_scopes = m_cust_id_scopes_map.find(l_id);
        if(i_scopes == m_cust_id_scopes_map.end())
        {

                WAFLZ_PERROR(m_err_msg, "customer id - %" PRIu64 " not found in the scopes map", l_id);
                if(l_rules) { delete l_rules; l_rules = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        l_s = i_scopes->second->load_rules(l_rules);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", i_scopes->second->get_err_msg());
                if(l_rules) { delete l_rules; l_rules = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details update custom rules config
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes_configs::load_rules(const char* a_buf, uint32_t a_buf_len)
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
        int32_t l_s;
       if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if(l_js->IsObject())
        {
                l_s = load_rules(l_js);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        if(l_js) { delete l_js; l_js = NULL;}
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
                        l_s = load_rules((void*)&l_e);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                if(m_enable_locking)
                                {
                                        pthread_mutex_unlock(&m_mutex);
                                }
                                if(l_js) { delete l_js; l_js = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        if(l_js) { delete l_js; l_js = NULL;}
        if(m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//: -----------------------------------------------------------------------------
//: \details update profile config
//: \return  TODO
//: \param   TODO
//: -----------------------------------------------------------------------------
int32_t scopes_configs::load_profile(void* a_js)
{
        int32_t l_s;
        ns_waflz::profile* l_profile = new profile(m_engine);
        l_s = l_profile->load(a_js);
         if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "profile loading failed");
                if(l_profile) { delete l_profile;l_profile = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        uint64_t l_id;
        const std::string& l_cust_id = l_profile->get_cust_id();
        l_s = ns_waflz::convert_hex_to_uint(l_id, l_cust_id.c_str());
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg,"conversion to uint failed\n");
                if(l_profile) { delete l_profile;l_profile = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        cust_id_scopes_map_t::iterator i_scopes;
        i_scopes = m_cust_id_scopes_map.find(l_id);
        if(i_scopes == m_cust_id_scopes_map.end())
        {

                WAFLZ_PERROR(m_err_msg, "customer id - %" PRIu64 " not found in the scopes map", l_id);
                if(l_profile) { delete l_profile; l_profile = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        l_s = i_scopes->second->load_profile(l_profile);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", i_scopes->second->get_err_msg());
                if(l_profile) { delete l_profile; l_profile = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: -----------------------------------------------------------------------------
//: \details update profile config
//: \return  TODO
//: \param   TODO
//: -----------------------------------------------------------------------------
int32_t scopes_configs::load_profile(const char* a_buf, uint32_t a_buf_len)
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
        int32_t l_s;
        if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if(l_js->IsObject())
        {
                l_s = load_profile(l_js);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        if(l_js) { delete l_js; l_js = NULL;}
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
                        l_s = load_profile((void*)&l_e);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                if(m_enable_locking)
                                {
                                        pthread_mutex_unlock(&m_mutex);
                                }
                                if(l_js) { delete l_js; l_js = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        if(l_js) { delete l_js; l_js = NULL;}
        if(m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
}
