//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/scopes.h"
#include "waflz/rqst_ctx.h"
#include "waflz/config_parser.h"
#include "waflz/acl.h"
#include "waflz/rules.h"
#include "waflz/bots.h"
#include "waflz/engine.h"
#include "waflz/rl_obj.h"
#include "waflz/limit.h"
#include "waflz/enforcer.h"
#include "waflz/challenge.h"
#include "waflz/trace.h"
#include "support/ndebug.h"
#include "support/base64.h"
#include "support/file_util.h"
#include "support/time_util.h"
#include "op/nms.h"
#include "op/regex.h"
#include "scope.pb.h"
#include "profile.pb.h"
#include "jspb/jspb.h"
#include "event.pb.h"
#include "limit.pb.h"
#include "rule.pb.h"
#include <fnmatch.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _SCOPES_MAX_SIZE (1024*1024)
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define VERIFY_HAS(_pb, _field) do { \
        if(!_pb.has_##_field()) { \
                WAFLZ_PERROR(m_err_msg, "missing %s field", #_field); \
                return WAFLZ_STATUS_ERROR; \
        } \
} while(0)
#define _GET_HEADER(_header) do { \
    l_d.m_data = _header; \
    l_d.m_len = sizeof(_header); \
    data_map_t::const_iterator i_h = a_ctx->m_header_map.find(l_d); \
    if(i_h != a_ctx->m_header_map.end()) \
    { \
            l_v.m_data = i_h->second.m_data; \
            l_v.m_len = i_h->second.m_len; \
    } \
    } while(0)
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! utils
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t compile_action(waflz_pb::enforcement& ao_axn, char* ao_err_msg)
{
        // -------------------------------------------------
        // convert type string to enf_type
        // -------------------------------------------------
        if(!ao_axn.has_enf_type() &&
            ao_axn.has_type())
        {
                const std::string &l_type = ao_axn.type();
#define _ELIF_TYPE(_str, _type) else \
if(strncasecmp(l_type.c_str(), _str, sizeof(_str)) == 0) { \
        ao_axn.set_enf_type(waflz_pb::enforcement_type_t_##_type); \
}
            if(0) {}
            _ELIF_TYPE("REDIRECT_302", REDIRECT_302)
            _ELIF_TYPE("REDIRECT-302", REDIRECT_302)
            _ELIF_TYPE("REDIRECT_JS", REDIRECT_JS)
            _ELIF_TYPE("REDIRECT-JS", REDIRECT_JS)
            _ELIF_TYPE("HASHCASH", HASHCASH)
            _ELIF_TYPE("CUSTOM_RESPONSE", CUSTOM_RESPONSE)
            _ELIF_TYPE("CUSTOM-RESPONSE", CUSTOM_RESPONSE)
            _ELIF_TYPE("DROP_REQUEST", DROP_REQUEST)
            _ELIF_TYPE("DROP-REQUEST", DROP_REQUEST)
            _ELIF_TYPE("DROP_CONNECTION", DROP_CONNECTION)
            _ELIF_TYPE("DROP-CONNECTION", DROP_CONNECTION)
            _ELIF_TYPE("NOP", NOP)
            _ELIF_TYPE("ALERT", ALERT)
            _ELIF_TYPE("BLOCK_REQUEST", BLOCK_REQUEST)
            _ELIF_TYPE("BLOCK-REQUEST", BLOCK_REQUEST)
            _ELIF_TYPE("BROWSER_CHALLENGE", BROWSER_CHALLENGE)
            _ELIF_TYPE("BROWSER-CHALLENGE", BROWSER_CHALLENGE)
            _ELIF_TYPE("NULL_ALERT", NULL_ALERT)
            _ELIF_TYPE("NULL-ALERT", NULL_ALERT)
            _ELIF_TYPE("NULL_BLOCK", NULL_BLOCK)
            _ELIF_TYPE("NULL-BLOCK", NULL_BLOCK)
            _ELIF_TYPE("IGNORE_ALERT", IGNORE_ALERT)
            _ELIF_TYPE("IGNORE-ALERT", IGNORE_ALERT)
            _ELIF_TYPE("IGNORE_BLOCK", IGNORE_BLOCK)
            _ELIF_TYPE("IGNORE-BLOCK", IGNORE_BLOCK)
            else
            {
                    WAFLZ_PERROR(ao_err_msg, "unrecognized enforcement type string: %s", l_type.c_str());
                    return WAFLZ_STATUS_ERROR;
            }
        }
        // -------------------------------------------------
        // convert b64 encoded resp
        // -------------------------------------------------
        if(!ao_axn.has_response_body() &&
                        ao_axn.has_response_body_base64() &&
           !ao_axn.response_body_base64().empty())
        {
                const std::string& l_b64 = ao_axn.response_body_base64();
                char* l_body = NULL;
                size_t l_body_len = 0;
                int32_t l_s;
                l_s = b64_decode(&l_body, l_body_len, l_b64.c_str(), l_b64.length());
                if(!l_body ||
                   !l_body_len ||
                   (l_s != WAFLZ_STATUS_OK))
                {
                        WAFLZ_PERROR(ao_err_msg, "decoding response_body_base64 string: %s", l_b64.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                ao_axn.mutable_response_body()->assign(l_body, l_body_len);
                if(l_body) { free(l_body); l_body = NULL; }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details return short date in form "<mm>/<dd>/<YYYY>"
//! \return  None
//! \param   TODO
//! ----------------------------------------------------------------------------
static const char *get_date_short_str(void)
{
        // TODO thread caching???
        static char s_date_str[128];
        time_t l_time = time(NULL);
        struct tm* l_tm = localtime(&l_time);
        if(0 == strftime(s_date_str, sizeof(s_date_str), "%m/%d/%Y", l_tm))
        {
                return "1/1/1970";
        }
        else
        {
                return s_date_str;
        }
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  None
//! \param   TODO
//! ----------------------------------------------------------------------------
static int32_t add_limit_with_key(waflz_pb::limit &ao_limit,
                                  uint16_t a_key,
                                  rqst_ctx *a_ctx)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Set operator to streq for all
        // -------------------------------------------------
        const char *l_data = NULL;
        uint32_t l_len = 0;
        switch(a_key)
        {
        // -------------------------------------------------
        // ip
        // -------------------------------------------------
        case waflz_pb::limit_key_t_IP:
        {
                l_data = a_ctx->m_src_addr.m_data;
                l_len = a_ctx->m_src_addr.m_len;
                break;
        }
        // -------------------------------------------------
        // user-agent
        // -------------------------------------------------
        case waflz_pb::limit_key_t_USER_AGENT:
        {
                if(!a_ctx)
                {
                        break;
                }
                data_t l_d;
                data_t l_v;
                _GET_HEADER("User-Agent");
                l_data = l_v.m_data;
                l_len = l_v.m_len;
                break;
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        default:
        {
                //WAFLZ_PERROR(m_err_msg, "unrecognized dimension type: %u", a_key);
                return WAFLZ_STATUS_ERROR;
        }
        }
        // if no data -no limit
        if(!l_data ||
           (l_len == 0))
        {
                return WAFLZ_STATUS_OK;
        }
        // Add limit for any data
        waflz_pb::condition *l_c = NULL;
        if(ao_limit.condition_groups_size() > 0)
        {
                l_c = ao_limit.mutable_condition_groups(0)->add_conditions();
        }
        else
        {
                l_c = ao_limit.add_condition_groups()->add_conditions();
        }
        // -------------------------------------------------
        // set operator
        // -------------------------------------------------
        // always STREQ
        waflz_pb::op_t* l_operator = l_c->mutable_op();
        l_operator->set_type(waflz_pb::op_t_type_t_STREQ);
        l_operator->set_value(l_data, l_len);
        // -------------------------------------------------
        // set var
        // -------------------------------------------------
        waflz_pb::condition_target_t* l_var = l_c->mutable_target();
        switch(a_key)
        {
        // -------------------------------------------------
        // ip
        // -------------------------------------------------
        case waflz_pb::limit_key_t_IP:
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REMOTE_ADDR);
                break;
        }
        // -------------------------------------------------
        // user-agent
        // -------------------------------------------------
        case waflz_pb::limit_key_t_USER_AGENT:
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REQUEST_HEADERS);
                l_var->mutable_value()->assign("User-Agent");
                break;
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        default:
        {
                break;
        }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details ctor
//! \return  None
//! \param   TODO
//! ----------------------------------------------------------------------------
scopes::scopes(engine &a_engine, kv_db &a_kv_db, challenge& a_challenge):
        m_init(false),
        m_pb(NULL),
        m_err_msg(),
        m_engine(a_engine),
        m_db(a_kv_db),
        m_regex_list(),
        m_data_set_list(),
        m_data_case_i_set_list(),
        m_id(),
        m_cust_id(),
        m_account_type("__na__"),
        m_name(),
        m_id_acl_map(),
        m_id_rules_map(),
        m_id_profile_map(),
        m_id_limit_map(),
        m_id_bots_map(),
        m_enfx(NULL),
        m_challenge(a_challenge)
{
        m_pb = new waflz_pb::scope_config();
        m_enfx = new enforcer(false);
}
//! ----------------------------------------------------------------------------
//! \brief   dtor
//! \deatils
//! \return  None
//! ----------------------------------------------------------------------------
scopes::~scopes()
{
        if(m_pb) { delete m_pb; m_pb = NULL; }
        if(m_enfx) { delete m_enfx; m_enfx = NULL; }
        // -------------------------------------------------
        // clear parts...
        // -------------------------------------------------
#define _DEL_MAP(_t, _m) do { \
        for(_t::iterator i = _m.begin(); i != _m.end(); ++i) { \
                if(i->second) { delete i->second; i->second = NULL; } \
        } \
} while(0)
        _DEL_MAP(id_acl_map_t, m_id_acl_map);
        _DEL_MAP(id_rules_map_t, m_id_rules_map);
        _DEL_MAP(id_profile_map_t, m_id_profile_map);
        _DEL_MAP(id_limit_map_t, m_id_limit_map);
        _DEL_MAP(id_bots_map_t, m_id_bots_map);
        // -------------------------------------------------
        // destruct m_regex_list
        // -------------------------------------------------
        for(regex_list_t::iterator i_p = m_regex_list.begin();
            i_p != m_regex_list.end();
            ++i_p)
        {
                if(*i_p) { delete *i_p; *i_p = NULL;}
        }
        // -------------------------------------------------
        // destruct str_ptr_set_list
        // -------------------------------------------------
        for(data_set_list_t::iterator i_n = m_data_set_list.begin();
            i_n != m_data_set_list.end();
            ++i_n)
        {
                if(*i_n) { delete *i_n; *i_n = NULL;}
        }
        for(data_case_i_set_list_t::iterator i_n = m_data_case_i_set_list.begin();
            i_n != m_data_case_i_set_list.end();
            ++i_n)
        {
                if(*i_n) { delete *i_n; *i_n = NULL;}
        }
}
//! ----------------------------------------------------------------------------
//! \details compile_op
//! \return  0/-1
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::compile_op(::waflz_pb::op_t& ao_op)
{
        // -------------------------------------------------
        // check if exist...
        // -------------------------------------------------
        if(!ao_op.has_type())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // for type...
        // -------------------------------------------------
        switch(ao_op.type())
        {
        // -------------------------------------------------
        // regex
        // -------------------------------------------------
        case ::waflz_pb::op_t_type_t_RX:
        {
                if(!ao_op.has_value())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                const std::string &l_val = ao_op.value();
                regex* l_rx = new regex();
                int32_t l_s;
                l_s = l_rx->init(l_val.c_str(), l_val.length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "failed to compile regex: '%s'.", l_val.c_str());
                        delete l_rx;
                        l_rx = NULL;
                        return WAFLZ_STATUS_ERROR;
                }
                ao_op.set__reserved_1((uint64_t)(l_rx));
                m_regex_list.push_back(l_rx);
                break;
        }
        // -------------------------------------------------
        // exact condition list
        // -------------------------------------------------
        case ::waflz_pb::op_t_type_t_EM:
        {
                if(!ao_op.has_value() &&
                   !ao_op.values_size())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // case insensitive
                // -----------------------------------------
                if(ao_op.is_case_insensitive())
                {
                        data_case_i_set_t *l_ds = new data_case_i_set_t();
                        // ---------------------------------
                        // prefer values to value
                        // ---------------------------------
                        if(ao_op.values_size())
                        {
                                for(int32_t i_v = 0; i_v < ao_op.values_size(); ++i_v)
                                {
                                        if(ao_op.values(i_v).empty())
                                        {
                                                continue;
                                        }
                                        data_t l_d;
                                        l_d.m_data = ao_op.values(i_v).c_str();
                                        l_d.m_len = ao_op.values(i_v).length();
                                        l_ds->insert(l_d);
                                }
                        }
                        else if(!ao_op.value().empty())
                        {
                                data_t l_d;
                                l_d.m_data = ao_op.value().c_str();
                                l_d.m_len = ao_op.value().length();
                                l_ds->insert(l_d);
                        }
                        ao_op.set__reserved_1((uint64_t)(l_ds));
                        m_data_case_i_set_list.push_back(l_ds);
                }
                // -----------------------------------------
                // case sensitive
                // -----------------------------------------
                else
                {
                        data_set_t *l_ds = new data_set_t();
                        // ---------------------------------
                        // prefer values to value
                        // ---------------------------------
                        if(ao_op.values_size())
                        {
                                for(int32_t i_v = 0; i_v < ao_op.values_size(); ++i_v)
                                {
                                        if(ao_op.values(i_v).empty())
                                        {
                                                continue;
                                        }
                                        data_t l_d;
                                        l_d.m_data = ao_op.values(i_v).c_str();
                                        l_d.m_len = ao_op.values(i_v).length();
                                        l_ds->insert(l_d);
                                }
                        }
                        else if(!ao_op.value().empty())
                        {
                                data_t l_d;
                                l_d.m_data = ao_op.value().c_str();
                                l_d.m_len = ao_op.value().length();
                                l_ds->insert(l_d);
                        }
                        ao_op.set__reserved_1((uint64_t)(l_ds));
                        m_data_set_list.push_back(l_ds);
                }
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                break;
        }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  0/-1
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::compile(const std::string& a_conf_dir_path)
{
        if(m_init)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(!m_pb->has_id())
        {
                WAFLZ_PERROR(m_err_msg, "missing id field");
                return WAFLZ_STATUS_ERROR;
        }
        if(!m_pb->has_customer_id())
        {
                WAFLZ_PERROR(m_err_msg, "missing customer id field");
                return WAFLZ_STATUS_ERROR;
        }
        if(m_pb->has_account_type())
        {
                m_account_type = m_pb->account_type();
        }
        m_id = m_pb->id();
        m_cust_id = m_pb->customer_id();
        m_name = m_pb->name();
        // -------------------------------------------------
        // for each scope - compile op and load parts
        // -------------------------------------------------
        int32_t l_s;
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                if(l_sc.has_host())
                {
                        l_s = compile_op(*(l_sc.mutable_host()));
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                if(l_sc.has_path())
                {
                        l_s = compile_op(*(l_sc.mutable_path()));
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                l_s = load_parts(l_sc, a_conf_dir_path);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load(const char *a_buf, uint32_t a_buf_len, const std::string& a_conf_dir_path)
{
        if(a_buf_len > _SCOPES_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                             a_buf_len,
                             _SCOPES_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        // -------------------------------------------------
        // load from js object
        // -------------------------------------------------
        int32_t l_s;
        l_s = update_from_json(*m_pb, a_buf, a_buf_len);
        //TRC_DEBUG("whole config %s", m_pb->DebugString().c_str());
        if(l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // compile and load parts
        // -------------------------------------------------
        l_s = compile(a_conf_dir_path);
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load(void *a_js, const std::string& a_conf_dir_path)
{
        m_init = false;
        // -------------------------------------------------
        // load from js object
        // -------------------------------------------------
        const rapidjson::Document &l_js = *((rapidjson::Document *)a_js);
        int32_t l_s;
        l_s = update_from_json(*m_pb, l_js);
        if(l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // compile and load parts
        // -------------------------------------------------
        l_s = compile(a_conf_dir_path);
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_parts(waflz_pb::scope& a_scope,
                           const std::string& a_conf_dir_path)
{
        // -------------------------------------------------
        // acl audit
        // -------------------------------------------------
        if(a_scope.has_acl_audit_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_acl_map_t::iterator i_acl = m_id_acl_map.find(a_scope.acl_audit_id());
                if(i_acl != m_id_acl_map.end())
                {
                        a_scope.set__acl_audit__reserved((uint64_t)i_acl->second);
                        goto acl_audit_action;
                }
                // -----------------------------------------
                // make acl obj
                // -----------------------------------------
                acl *l_acl = new acl(m_engine);
                std::string l_path;
                l_path = a_conf_dir_path + "/acl/" + m_cust_id + "-" + a_scope.acl_audit_id() +".acl.json"; 
                char *l_buf = NULL;
                uint32_t l_buf_len;
                int32_t l_s;
                l_s = read_file(l_path.c_str(), &l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        // TODO cleanup...
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_acl->load(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_acl->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        // TODO cleanup...
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__acl_audit__reserved((uint64_t)l_acl);
                m_id_acl_map[a_scope.acl_audit_id()] = l_acl;
        }
acl_audit_action:
        // -------------------------------------------------
        // acl audit action
        // -------------------------------------------------
        if(a_scope.has_acl_audit_action())
        {
                waflz_pb::enforcement *l_a = a_scope.mutable_acl_audit_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // acl audit
        // -------------------------------------------------
        if(a_scope.has_acl_prod_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_acl_map_t::iterator i_acl = m_id_acl_map.find(a_scope.acl_prod_id());
                if(i_acl != m_id_acl_map.end())
                {
                        a_scope.set__acl_prod__reserved((uint64_t)i_acl->second);
                        goto acl_prod_action;
                }
                // -----------------------------------------
                // make acl obj
                // -----------------------------------------
                acl *l_acl = new acl(m_engine);
                std::string l_path;
                l_path = a_conf_dir_path + "/acl/" + m_cust_id + "-" + a_scope.acl_prod_id() +".acl.json";
                int32_t l_s;
                char *l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_path.c_str(), &l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if(l_acl) { delete l_acl; l_acl = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_acl->load(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_acl->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if(l_acl) { delete l_acl; l_acl = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__acl_prod__reserved((uint64_t)l_acl);
                m_id_acl_map[a_scope.acl_prod_id()] = l_acl;
        }
acl_prod_action:
        // -------------------------------------------------
        // acl prod action
        // -------------------------------------------------
        if(a_scope.has_acl_prod_action())
        {
                waflz_pb::enforcement *l_a = a_scope.mutable_acl_prod_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // bots prod
        // -------------------------------------------------
        if(a_scope.has_bots_prod_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_bots_map_t::iterator i_bots = m_id_bots_map.find(a_scope.bots_prod_id());
                if(i_bots != m_id_bots_map.end())
                {
                        a_scope.set__bots_prod__reserved((uint64_t)i_bots->second);
                        goto bots_prod_action;
                }
                // -----------------------------------------
                // make bots obj
                // -----------------------------------------
                std::string l_path;
                l_path = a_conf_dir_path + "/bots/" + m_cust_id + "-" + a_scope.bots_prod_id() +".bots.json";
                bots* l_bots = new bots(m_engine, m_challenge);
                int32_t l_s;
                l_s = l_bots->load_file(l_path.c_str(), l_path.length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading bots (prod) conf file: %s. reason: %s\n",
                                   l_path.c_str(),
                                   l_bots->get_err_msg());
                        if(l_bots) { delete l_bots; l_bots = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__bots_prod__reserved((uint64_t)l_bots);
                m_id_bots_map[a_scope.bots_prod_id()] = l_bots;
        }
bots_prod_action:
        // -------------------------------------------------
        //  bots prod action
        // -------------------------------------------------
        if(a_scope.has_bots_prod_action())
        {
                waflz_pb::enforcement *l_a = a_scope.mutable_bots_prod_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }       
        }
        // -------------------------------------------------
        // rules audit
        // -------------------------------------------------
        if(a_scope.has_rules_audit_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_rules_map_t::iterator i_rules = m_id_rules_map.find(a_scope.rules_audit_id());
                if(i_rules != m_id_rules_map.end())
                {
                        a_scope.set__rules_audit__reserved((uint64_t)i_rules->second);
                        goto rules_audit_action;
                }
                // -----------------------------------------
                // make rules obj
                // -----------------------------------------
                std::string l_path;
                l_path = a_conf_dir_path + "/rules/" + m_cust_id + "-" + a_scope.rules_audit_id() +".rules.json";
                rules *l_rules = new rules(m_engine);
                int32_t l_s;
                l_s = l_rules->load_file(l_path.c_str(), l_path.length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading rules (audit) conf file: %s. reason: %s\n",
                                   l_path.c_str(),
                                   "__na__");
                                   // TODO -get reason...
                                   //l_wafl->get_err_msg());
                        if(l_rules) { delete l_rules; l_rules = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__rules_audit__reserved((uint64_t)l_rules);
                m_id_rules_map[a_scope.rules_audit_id()] = l_rules;
        }
rules_audit_action:
        // -------------------------------------------------
        // rules audit action
        // -------------------------------------------------
        if(a_scope.has_rules_audit_action())
        {
                waflz_pb::enforcement *l_a = a_scope.mutable_rules_audit_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // rules prod
        // -------------------------------------------------
        if(a_scope.has_rules_prod_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_rules_map_t::iterator i_rules = m_id_rules_map.find(a_scope.rules_prod_id());
                if(i_rules != m_id_rules_map.end())
                {
                        a_scope.set__rules_prod__reserved((uint64_t)i_rules->second);
                        goto rules_prod_action;
                }
                // -----------------------------------------
                // make rules obj
                // -----------------------------------------
                std::string l_path;
                l_path = a_conf_dir_path + "/rules/" + m_cust_id + "-" + a_scope.rules_prod_id() +".rules.json";
                rules *l_rules = new rules(m_engine);
                int32_t l_s;
                l_s = l_rules->load_file(l_path.c_str(), l_path.length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading rules (prod) conf file: %s. reason: %s\n",
                                   l_path.c_str(),
                                   "__na__");
                                   // TODO -get reason...
                                   //l_wafl->get_err_msg());
                        if(l_rules) { delete l_rules; l_rules = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__rules_prod__reserved((uint64_t)l_rules);
                m_id_rules_map[a_scope.rules_prod_id()] = l_rules;
        }
rules_prod_action:
        // -------------------------------------------------
        // rules prod action
        // -------------------------------------------------
        if(a_scope.has_rules_prod_action())
        {
                waflz_pb::enforcement *l_a = a_scope.mutable_rules_prod_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // profile audit
        // -------------------------------------------------
        if(a_scope.has_profile_audit_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_profile_map_t::iterator i_profile = m_id_profile_map.find(a_scope.profile_audit_id());
                if(i_profile != m_id_profile_map.end())
                {
                        a_scope.set__profile_audit__reserved((uint64_t)i_profile->second);
                        goto profile_audit_action;
                }
                // -----------------------------------------
                // make profile obj
                // -----------------------------------------
                std::string l_path;
                l_path = a_conf_dir_path + "/profile/" + m_cust_id + "-" + a_scope.profile_audit_id() +".wafprof.json";
                profile *l_profile = new profile(m_engine);
                int32_t l_s;
                char *l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_path.c_str(), &l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if(l_profile) { delete l_profile; l_profile = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_profile->load(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_profile->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                       if(l_profile) { delete l_profile; l_profile = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__profile_audit__reserved((uint64_t)l_profile);
                m_id_profile_map[a_scope.profile_audit_id()] = l_profile;
        }
profile_audit_action:
        // -------------------------------------------------
        // acl audit action
        // -------------------------------------------------
        if(a_scope.has_profile_audit_action())
        {
                waflz_pb::enforcement *l_a = a_scope.mutable_profile_audit_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // profile prod
        // -------------------------------------------------
        if(a_scope.has_profile_prod_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_profile_map_t::iterator i_profile = m_id_profile_map.find(a_scope.profile_prod_id());
                if(i_profile != m_id_profile_map.end())
                {
                        a_scope.set__profile_prod__reserved((uint64_t)i_profile->second);
                        goto profile_prod_action;
                }
                // -----------------------------------------
                // make profile obj
                // -----------------------------------------
                std::string l_path;
                l_path = a_conf_dir_path + "/profile/" + m_cust_id + "-" + a_scope.profile_prod_id() +".wafprof.json";
                profile *l_profile = new profile(m_engine);
                int32_t l_s;
                char *l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_path.c_str(), &l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if(l_profile) { delete l_profile; l_profile = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_profile->load(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_profile->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if(l_profile) { delete l_profile; l_profile = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__profile_prod__reserved((uint64_t)l_profile);
                m_id_profile_map[a_scope.profile_prod_id()] = l_profile;
        }
profile_prod_action:
        // -------------------------------------------------
        // acl audit action
        // -------------------------------------------------
        if(a_scope.has_profile_prod_action())
        {
                waflz_pb::enforcement *l_a = a_scope.mutable_profile_prod_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // limits
        // -------------------------------------------------
        for(int i_l = 0; i_l < a_scope.limits_size(); ++i_l)
        {
                if(!a_scope.limits(i_l).has_id())
                {
                        continue;
                }
                const std::string& l_id = a_scope.limits(i_l).id();
                // -----------------------------------------
                // check exist...
                // -----------------------------------------
                id_limit_map_t::iterator i_limit = m_id_limit_map.find(l_id);
                if(i_limit != m_id_limit_map.end())
                {
                        a_scope.mutable_limits(i_l)->set__reserved_1((uint64_t)i_limit->second);
                        goto limit_action;
                }
                {
                // -----------------------------------------
                // make limit obj
                // -----------------------------------------
                std::string l_path;
                l_path = a_conf_dir_path + "/limit/" + m_cust_id + "-" + l_id +".limit.json";
                limit *l_limit = new limit(m_db);
                int32_t l_s;
                char *l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_path.c_str(), &l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if(l_limit) { delete l_limit; l_limit = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_limit->load(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_limit->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if(l_limit) { delete l_limit; l_limit = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.mutable_limits(i_l)->set__reserved_1((uint64_t)l_limit);
                m_id_limit_map[l_id] = l_limit;
                }
limit_action:
                // -----------------------------------------
                // limit action
                // -----------------------------------------
                if(a_scope.limits(i_l).has_action())
                {
                        waflz_pb::enforcement *l_a = a_scope.mutable_limits(i_l)->mutable_action();
                        int32_t l_s;
                        l_s = compile_action(*l_a, m_err_msg);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        //NDBG_PRINT("%s\n", a_scope.DebugString().c_str());
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details extern function to call process and pass on event info
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::process_request_plugin(char **ao_event,
                                       void *a_ctx,
                                       const rqst_ctx_callbacks *a_callbacks,
                                       rqst_ctx **ao_rqst_ctx)
{
        waflz_pb::event *l_audit_event = NULL;
        waflz_pb::event *l_prod_event = NULL;
        const waflz_pb::enforcement *l_enf = NULL;
        int32_t l_s;
        l_s = process(&l_enf, &l_audit_event, &l_prod_event, a_ctx, PART_MK_ALL, a_callbacks, ao_rqst_ctx);
        // TODO: dev handle both audit and prod
        if(l_prod_event)
        {

                int32_t l_len = strlen(l_prod_event->DebugString().c_str());
                char *l_event = (char*)malloc(sizeof(char) * l_len + 1);
                strncpy(l_event, l_prod_event->DebugString().c_str(), l_len);
                *ao_event = l_event;
        }
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::process(const waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        const rqst_ctx_callbacks *a_callbacks,
                        rqst_ctx **ao_rqst_ctx)
{
        if(!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create rqst_ctx
        // -------------------------------------------------
        rqst_ctx *l_ctx = NULL;
        // TODO -fix args!!!
        //l_rqst_ctx = new rqst_ctx(a_ctx, l_body_size_max, m_waf->get_parse_json());
        l_ctx = new rqst_ctx(a_ctx, DEFAULT_BODY_SIZE_MAX, a_callbacks);
        if(ao_rqst_ctx)
        {
                *ao_rqst_ctx = l_ctx;
        }
        // -------------------------------------------------
        // run phase 1 init
        // -------------------------------------------------
        int32_t l_s;
        l_s = l_ctx->init_phase_1(m_engine.get_geoip2_mmdb(), NULL, NULL, NULL);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if(!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // for each scope...
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                const ::waflz_pb::scope& l_sc = m_pb->scopes(i_s);
                bool l_m;
                l_s = in_scope(l_m, l_sc, l_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO -log error???
                        if(!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // no match continue to next check...
                // -----------------------------------------
                if(!l_m)
                {
                        continue;
                }
                // -----------------------------------------
                // process scope and mark request as analyzed
                // for waf and rl. It doesnt matter whether
                // a scope has rl or waf enabled, if it hits the
                // scope, we will not double process it
                // -----------------------------------------
                (*ao_rqst_ctx)->m_waf_analyzed = true;
                (*ao_rqst_ctx)->m_limit_analyzed = true;
                l_s = process(ao_enf, ao_audit_event, ao_prod_event, l_sc, a_ctx, a_part_mk, ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO -log error???
                        if(!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // Log scope id and name
                // that generated an event
                // -----------------------------------------
                if(*ao_audit_event)
                {
                        (*ao_audit_event)->set_scope_config_id(l_sc.id());
                        (*ao_audit_event)->set_scope_config_name(l_sc.name());
                        (*ao_audit_event)->set_account_type(m_account_type);
                }
                if(*ao_prod_event)
                {
                        (*ao_prod_event)->set_scope_config_id(l_sc.id());
                        (*ao_prod_event)->set_scope_config_name(l_sc.name());
                        (*ao_prod_event)->set_account_type(m_account_type);
                }
                // -----------------------------------------
                // break out on first scope match
                // -----------------------------------------
                break;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details if a_loaded_date is >= a_new_Date
//! \return  False
//! \param   TODO
//! ----------------------------------------------------------------------------
bool scopes::compare_dates(const char* a_loaded_date, const char* a_new_date)
{
        if(a_loaded_date == NULL ||
           a_new_date == NULL)
        {
                return false;
        }
        uint64_t l_loaded_epoch = get_epoch_seconds(a_loaded_date, CONFIG_DATE_FORMAT);
        uint64_t l_new_epoch = get_epoch_seconds(a_new_date, CONFIG_DATE_FORMAT);
        if(l_loaded_epoch >= l_new_epoch)
        {
                return false;
        }
        return true;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_limit(ns_waflz::limit* a_limit)
{
        if(!a_limit)
        {
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_id = a_limit->get_id();
        // -------------------------------------------------
        // check id in map
        // -------------------------------------------------
        id_limit_map_t::iterator i_t = m_id_limit_map.find(l_id);
        if(i_t == m_id_limit_map.end())
        {
                WAFLZ_PERROR(m_err_msg, "limit id %s not attached to any scopes", l_id.c_str());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check if limit is latest
        // -------------------------------------------------
        const waflz_pb::limit* l_old_pb = i_t->second->get_pb();
        const waflz_pb::limit* l_new_pb = a_limit->get_pb();
        if((l_old_pb != NULL) &&
           (l_new_pb != NULL) &&
           (l_old_pb->has_last_modified_date()) &&
           (l_new_pb->has_last_modified_date()))
        {
                if(!compare_dates(l_old_pb->last_modified_date().c_str(),
                                  l_new_pb->last_modified_date().c_str()))
                {
                        if(a_limit) { delete a_limit; a_limit = NULL; }
                        return WAFLZ_STATUS_OK;
                }
        }
        if(i_t->second) { delete i_t->second; i_t->second = NULL;}
        i_t->second = a_limit;
        // -------------------------------------------------
        // update scope's reserved fields
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                for(int i_l = 0; i_l < l_sc.limits_size(); ++i_l)
                {       
                        ::waflz_pb::scope_limit_config* l_slc = l_sc.mutable_limits(i_l);
                        if(l_slc->id() == l_id)
                        {
                                l_slc->set__reserved_1((uint64_t)a_limit);
                                break;
                        }
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_acl(ns_waflz::acl* a_acl)
{
        if(!a_acl)
        {
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_id = a_acl->get_id();
        // -------------------------------------------------
        // check id in map
        // -------------------------------------------------
        id_acl_map_t::iterator i_t = m_id_acl_map.find(l_id);
        if(i_t == m_id_acl_map.end())
        {
                if(a_acl) { delete a_acl; a_acl = NULL; }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check if acl is latest
        // -------------------------------------------------
        const waflz_pb::acl* l_old_pb = i_t->second->get_pb();
        const waflz_pb::acl* l_new_pb = a_acl->get_pb();
        if((l_old_pb != NULL) &&
           (l_new_pb != NULL) &&
           (l_old_pb->has_last_modified_date()) &&
           (l_new_pb->has_last_modified_date()))
        {
                if(!compare_dates(l_old_pb->last_modified_date().c_str(),
                                  l_new_pb->last_modified_date().c_str()))
                {
                        if(a_acl) { delete a_acl; a_acl = NULL; }
                        return WAFLZ_STATUS_OK;
                }
        }
        if(i_t->second) { delete i_t->second; i_t->second = NULL;}
        i_t->second = a_acl;
        // -------------------------------------------------
        // update scope's reserved fields
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                if(l_sc.has_acl_audit_id() &&
                   l_sc.acl_audit_id() == l_id)
                {
                        l_sc.set__acl_audit__reserved((uint64_t)a_acl);
                }
                if(l_sc.has_acl_prod_id() &&
                   l_sc.acl_prod_id() == l_id)
                {
                        l_sc.set__acl_prod__reserved((uint64_t)a_acl);
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_rules(ns_waflz::rules* a_rules)
{
        if(!a_rules)
        {
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_id = a_rules->get_id();
        // -------------------------------------------------
        // check id in map
        // -------------------------------------------------
        id_rules_map_t::iterator i_t = m_id_rules_map.find(l_id);
        if(i_t == m_id_rules_map.end())
        {
                if(a_rules) {delete a_rules; a_rules = NULL;}
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check if rules is latest
        // -------------------------------------------------
        const waflz_pb::sec_config_t* l_old_pb = i_t->second->get_pb();
        const waflz_pb::sec_config_t* l_new_pb = a_rules->get_pb();
        if((l_old_pb != NULL) &&
           (l_new_pb != NULL) &&
           (l_old_pb->has_last_modified_date()) &&
           (l_new_pb->has_last_modified_date()))
        {
                if(!compare_dates(l_old_pb->last_modified_date().c_str(),
                                  l_new_pb->last_modified_date().c_str()))
                {
                        if(a_rules) { delete a_rules; a_rules = NULL; }
                        return WAFLZ_STATUS_OK;
                }
        }
        if(i_t->second) { delete i_t->second; i_t->second = NULL;}
        i_t->second = a_rules;
        // -------------------------------------------------
        // update scope's reserved fields
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                if(l_sc.has_rules_audit_id() &&
                   l_sc.rules_audit_id() == l_id)
                {
                        l_sc.set__rules_audit__reserved((uint64_t)a_rules);
                }
                if(l_sc.has_rules_prod_id() &&
                   l_sc.rules_prod_id() == l_id)
                {
                        l_sc.set__rules_prod__reserved((uint64_t)a_rules);
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_bots(ns_waflz::bots* a_bots)
{
        if(!a_bots)
        {
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_id = a_bots->get_id();
        // -------------------------------------------------
        // check id in map
        // -------------------------------------------------
        id_bots_map_t::iterator i_t = m_id_bots_map.find(l_id);
        if(i_t == m_id_bots_map.end())
        {
                if(a_bots) { delete a_bots; a_bots = NULL; }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check if bots is latest
        // -------------------------------------------------
        const waflz_pb::sec_config_t* l_old_pb = i_t->second->get_pb();
        const waflz_pb::sec_config_t* l_new_pb = a_bots->get_pb();
        if((l_old_pb != NULL) &&
           (l_new_pb != NULL) &&
           (l_old_pb->has_last_modified_date()) &&
           (l_new_pb->has_last_modified_date()))
        {
                if(!compare_dates(l_old_pb->last_modified_date().c_str(),
                                  l_new_pb->last_modified_date().c_str()))
                {
                        if(a_bots) { delete a_bots; a_bots = NULL; }
                        return WAFLZ_STATUS_OK;
                }
        }
        if(i_t->second) { delete i_t->second; i_t->second = NULL;}
        i_t->second = a_bots;
        // -------------------------------------------------
        // update scope's reserved fields
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                if(l_sc.has_bots_prod_id() &&
                   l_sc.bots_prod_id() == l_id)
                {
                        l_sc.set__bots_prod__reserved((uint64_t)a_bots);
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_profile(ns_waflz::profile* a_profile)
{
        if(!a_profile)
        {
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_id = a_profile->get_id();
        // -------------------------------------------------
        // check id in map
        // -------------------------------------------------
        id_profile_map_t::iterator i_t = m_id_profile_map.find(l_id);
        if(i_t == m_id_profile_map.end())
        {
                if(a_profile) { delete a_profile; a_profile = NULL; }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check if profile is latest
        // -------------------------------------------------
        const waflz_pb::profile* l_old_pb = i_t->second->get_pb();
        const waflz_pb::profile* l_new_pb = a_profile->get_pb();
        if((l_old_pb != NULL) &&
           (l_new_pb != NULL) &&
           (l_old_pb->has_last_modified_date()) &&
           (l_new_pb->has_last_modified_date()))
        {
                if(!compare_dates(l_old_pb->last_modified_date().c_str(),
                                  l_new_pb->last_modified_date().c_str()))
                {
                        if(a_profile) { delete a_profile; a_profile = NULL; }
                        return WAFLZ_STATUS_OK;
                }
        }
        if(i_t->second) { delete i_t->second; i_t->second = NULL;}
        i_t->second = a_profile;
        // -------------------------------------------------
        // update scope's reserved fields
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));

                if(l_sc.has_profile_audit_id() &&
                    l_sc.profile_audit_id() == l_id)
                {
                        l_sc.set__profile_audit__reserved((uint64_t)a_profile);
                }       
                if(l_sc.has_profile_prod_id() &&
                    l_sc.profile_prod_id() == l_id)
                {
                        l_sc.set__profile_prod__reserved((uint64_t)a_profile);
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::process(const waflz_pb::enforcement** ao_enf,
                        waflz_pb::event** ao_audit_event,
                        waflz_pb::event** ao_prod_event,
                        const ::waflz_pb::scope& a_scope,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        rqst_ctx **ao_rqst_ctx)
{
        // -------------------------------------------------
        // sanity checking
        // -------------------------------------------------
        if(!ao_enf ||
           !ao_audit_event ||
           !ao_prod_event)
        {
                // TODO reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // clear ao_* inputs
        // -------------------------------------------------
        *ao_enf = NULL;
        *ao_audit_event = NULL;
        *ao_prod_event = NULL;
        // -------------------------------------------------
        // *************************************************
        //                   A U D I T
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // acl
        // -------------------------------------------------
        if((a_part_mk & PART_MK_ACL) &&
           a_scope.has__acl_audit__reserved())
        {
                acl *l_acl = (acl *)a_scope._acl_audit__reserved();
                waflz_pb::event *l_event = NULL;
                bool l_wl = false;
                int32_t l_s;
                l_s = l_acl->process(&l_event, l_wl, a_ctx, ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_event) { delete l_event; l_event = NULL; }
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_wl)
                {
                        goto prod;
                }
                if(!l_event)
                {
                        goto audit_rules;
                }
                l_s = (*ao_rqst_ctx)->append_rqst_info(*l_event, m_engine.get_geoip2_mmdb());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::append_rqst_info for acl");
                        return WAFLZ_STATUS_ERROR;
                }
                *ao_audit_event = l_event;
                goto prod;
        }
        // -------------------------------------------------
        // rules
        // -------------------------------------------------
audit_rules:
        if((a_part_mk & PART_MK_RULES) &&
           a_scope.has__rules_audit__reserved())
        {
                rules *l_rules = (rules *)a_scope._rules_audit__reserved();
                waflz_pb::event *l_event = NULL;
                int32_t l_s;
                l_s = l_rules->process(&l_event, a_ctx, ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_event) { delete l_event; l_event = NULL; }
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_event)
                {
                        goto audit_profile;
                }
                l_event->set_rules_config_id(l_rules->get_id());
                l_event->set_rules_config_name(l_rules->get_name());
                *ao_audit_event = l_event;
                goto prod;
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
audit_profile:
        if((a_part_mk & PART_MK_WAF) &&
           a_scope.has__profile_audit__reserved())
        {
                int32_t l_s;
                // -----------------------------------------
                // reset phase 1 to handle ignore...
                // -----------------------------------------
                l_s = (*ao_rqst_ctx)->reset_phase_1();
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // profile process
                // -----------------------------------------
                profile *l_profile = (profile *)a_scope._profile_audit__reserved();
                waflz_pb::event *l_event = NULL;
                l_s = l_profile->process(&l_event, a_ctx, PART_MK_WAF, ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_event) { delete l_event; l_event = NULL; }
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_event)
                {
                        goto prod;
                }
                *ao_audit_event = l_event;
                goto prod;
        }
        // -------------------------------------------------
        // *************************************************
        //                    P R O D
        // *************************************************
        // -------------------------------------------------
prod:
        // -------------------------------------------------
        // acl
        // -------------------------------------------------
        if((a_part_mk & PART_MK_ACL) &&
           a_scope.has__acl_prod__reserved())
        {
                acl *l_acl = (acl *)a_scope._acl_prod__reserved();
                waflz_pb::event *l_event = NULL;
                bool l_wl = false;
                int32_t l_s;
                l_s = l_acl->process(&l_event, l_wl, a_ctx, ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_event) { delete l_event; l_event = NULL; }
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_wl)
                {
                        goto done;
                }
                if(!l_event)
                {
                        goto enforcements;
                }
                l_s = (*ao_rqst_ctx)->append_rqst_info(*l_event, m_engine.get_geoip2_mmdb());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::append_rqst_info for acl");
                        return WAFLZ_STATUS_ERROR;
                }
                *ao_prod_event = l_event;
                if(a_scope.has_acl_prod_action())
                {
                        *ao_enf = &(a_scope.acl_prod_action());
                        if((*ao_enf)->has_status())
                        {
                                (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
                        }
                }
                goto done;
        }
        // -------------------------------------------------
        // enforcements
        // -------------------------------------------------
enforcements:
        if(!m_enfx)
        {
                goto limits;
        }
        if(a_part_mk & PART_MK_LIMITS)
        {
                int32_t l_s;
                l_s = m_enfx->process(ao_enf, *ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing enforcer process");
                        return WAFLZ_STATUS_ERROR;
                }
                if(*ao_enf)
                {
                        //TODO: handle browser challenge validation
                        if((*ao_enf)->has_status())
                        {
                                (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
                        }
                        goto done;
                }
        }
limits:
        // -------------------------------------------------
        // limits
        // -------------------------------------------------
        if(a_part_mk & PART_MK_LIMITS)
        {
                for(int i_l = 0; i_l < a_scope.limits_size(); ++i_l)
                {
                        int32_t l_s;
                        const ::waflz_pb::scope_limit_config& l_slc = a_scope.limits(i_l);
                        if(!l_slc.has__reserved_1())
                        {
                                continue;
                        }
                        limit *l_limit = (limit *)l_slc._reserved_1();
                        bool l_exceeds = false;
                        const waflz_pb::condition_group *l_cg = NULL;
                        l_s = l_limit->process(l_exceeds, &l_cg, a_scope.id(), *ao_rqst_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "performing limit process.");
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(!l_exceeds)
                        {
                                continue;
                        }
                        if(!l_slc.has_action())
                        {
                                continue;
                        }
                        // ---------------------------------
                        // signal new enforcement
                        // ---------------------------------
                        (*ao_rqst_ctx)->m_signal_enf = true;
                        // ---------------------------------
                        // add new exceeds
                        // ---------------------------------
                        const waflz_pb::enforcement& l_axn = l_slc.action();
                        waflz_pb::config *l_cfg = NULL;
                        l_s = add_exceed_limit(&l_cfg,
                                               *(l_limit->get_pb()),
                                               l_cg,
                                               l_axn,
                                               a_scope,
                                               *ao_rqst_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "performing add_exceed_limit");
                                return WAFLZ_STATUS_ERROR;
                        }
                        //const ::waflz_pb::enforcement& l_a = a_scope.limits(i_l).action();
                        // ---------------------------------
                        // merge enforcement
                        // ---------------------------------
                        //NDBG_OUTPUT("l_enfx: %s\n", l_enfcr->ShortDebugString().c_str());
                        l_s = m_enfx->merge(*l_cfg);
                        // TODO -return enforcer...
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "%s", m_enfx->get_err_msg());
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(l_cfg) { delete l_cfg; l_cfg = NULL; }
                        // ---------------------------------
                        // process enforcer
                        // ---------------------------------
                        l_s = m_enfx->process(ao_enf, *ao_rqst_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // enforced???
                        // ---------------------------------
                        if(*ao_enf)
                        {
                                if((*ao_enf)->has_status())
                                {
                                        (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
                                }
                                goto done;
                        }
                }
        }
        // -------------------------------------------------
        // bots
        // -------------------------------------------------
        if((a_part_mk & PART_MK_BOTS) &&
           a_scope.has__bots_prod__reserved())
        {
                // -----------------------------------------
                // process
                // -----------------------------------------
                bots* l_bots = (bots*)a_scope._bots_prod__reserved();
                waflz_pb::event *l_event = NULL;
                waflz_pb::enforcement *l_repdb_enf = NULL;
                const waflz_pb::enforcement *l_scope_enf = &(a_scope.bots_prod_action());
                int32_t l_s;
                l_s = l_bots->process(&l_event, a_ctx, &l_repdb_enf, &l_scope_enf, ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg, "%s", l_bots->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_event)
                {
                        goto prod_rules;
                }
                l_event->set_bots_config_id(l_bots->get_id());
                l_event->set_bots_config_name(l_bots->get_name());
                *ao_prod_event = l_event;
                if(l_repdb_enf)
                {
                        *ao_enf = l_repdb_enf;
                }
                else if(a_scope.has_bots_prod_action() &&
                        !(*ao_rqst_ctx)->m_bot_repdb_enf)
                {
                        *ao_enf = l_scope_enf;
                        if((*ao_enf)->has_status())
                        {
                                (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
                        }
                }
                goto done;
        }
prod_rules:
        // -------------------------------------------------
        // rules
        // -------------------------------------------------
        if((a_part_mk & PART_MK_RULES) &&
           a_scope.has__rules_prod__reserved())
        {
                // -----------------------------------------
                // process
                // -----------------------------------------
                rules *l_rules = (rules *)a_scope._rules_prod__reserved();
                waflz_pb::event *l_event = NULL;
                int32_t l_s;
                l_s = l_rules->process(&l_event, a_ctx, ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_event) { delete l_event; l_event = NULL; }
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_event)
                {
                        goto prod_profile;
                }
                l_event->set_rules_config_id(l_rules->get_id());
                l_event->set_rules_config_name(l_rules->get_name());
                *ao_prod_event = l_event;
                if(a_scope.has_rules_prod_action())
                {
                        *ao_enf = &(a_scope.rules_prod_action());;
                        if((*ao_enf)->has_status())
                        {
                                (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
                        }
                }
                goto done;
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
prod_profile:
        if((a_part_mk & PART_MK_WAF) &&
           a_scope.has__profile_prod__reserved())
        {
                // -----------------------------------------
                // reset phase 1 to handle ignore...
                // -----------------------------------------
                int32_t l_s;
                l_s = (*ao_rqst_ctx)->reset_phase_1();
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // profile process
                // -----------------------------------------
                profile *l_profile = (profile *)a_scope._profile_prod__reserved();
                waflz_pb::event *l_event = NULL;
                l_s = l_profile->process(&l_event, a_ctx, PART_MK_WAF, ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_event) { delete l_event; l_event = NULL; }
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_event)
                {
                        goto done;
                }
                *ao_prod_event = l_event;
                if(a_scope.has_profile_prod_action())
                {
                        *ao_enf = &(a_scope.profile_prod_action());
                        if((*ao_enf)->has_status())
                        {
                                (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
                        }
                }
                goto done;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
done:
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::add_exceed_limit(waflz_pb::config **ao_cfg,
                                 const waflz_pb::limit& a_limit,
                                 const waflz_pb::condition_group *a_condition_group,
                                 const waflz_pb::enforcement &a_action,
                                 const waflz_pb::scope& a_scope,
                                 rqst_ctx *a_ctx)
{
        if(!ao_cfg)
        {
                WAFLZ_PERROR(m_err_msg, "enforcer ptr NULL.");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create enforcement
        // -------------------------------------------------
        waflz_pb::config *l_cfg = new waflz_pb::config();
        l_cfg->set_id("__na__");
        l_cfg->set_name("__na__");
        l_cfg->set_type(waflz_pb::config_type_t_ENFORCER);
        l_cfg->set_customer_id(m_cust_id);
        l_cfg->set_enabled_date(get_date_short_str());
        // -------------------------------------------------
        // populate limit info
        // -------------------------------------------------
        waflz_pb::limit* l_limit = l_cfg->add_limits();
        l_limit->set_id(a_limit.id());
        l_limit->set_customer_id(m_cust_id);
        if(a_limit.has_name())
        {
            l_limit->set_name(a_limit.name());
        }
        else
        {
                l_limit->set_name("__na__");
        }
        l_limit->set_disabled(false);
        // -------------------------------------------------
        // copy "the limit"
        // -------------------------------------------------
        if(a_condition_group)
        {
                waflz_pb::condition_group *l_cg = l_limit->add_condition_groups();
                l_cg->CopyFrom(*a_condition_group);
        }
        waflz_pb::scope* l_sc = l_limit->mutable_scope();
        if(a_scope.has_host())
        {
                l_sc->mutable_host()->CopyFrom(a_scope.host());
        }
        if(a_scope.has_path())
        {
                l_sc->mutable_path()->CopyFrom(a_scope.path());
        }
        if(a_scope.has_id())
        {
                l_sc->set_id(a_scope.id());
        }
        if(a_scope.has_name())
        {
                l_sc->set_name(a_scope.name());
        }
        // -------------------------------------------------
        // create limits for dimensions
        // -------------------------------------------------
        for(int i_k = 0; i_k < a_limit.keys_size(); ++i_k)
        {
                int32_t l_s;
                l_s = add_limit_with_key(*l_limit,
                                         a_limit.keys(i_k),
                                         a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO cleanup
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // copy action(s)
        // -------------------------------------------------
        uint64_t l_cur_time_ms = get_time_ms();
        uint32_t l_e_duration_s = 0;
        waflz_pb::enforcement *l_e = l_limit->mutable_action();
        l_e->CopyFrom(a_action);
        // -------------------------------------------------
        // only id/name/type might be set
        // -------------------------------------------------
        l_e->set_start_time_ms(l_cur_time_ms);
        // -------------------------------------------------
        // TODO set percentage to 100 for now
        // -------------------------------------------------
        l_e->set_percentage(100.0);
        // -------------------------------------------------
        // duration calculation
        // -------------------------------------------------
        if(l_e->has_duration_sec())
        {
                l_e_duration_s = l_e->duration_sec();
        }
        else
        {
                l_e_duration_s = a_limit.duration_sec();
        }
        l_e->set_duration_sec(l_e_duration_s);
        // -------------------------------------------------
        // set duration
        // -------------------------------------------------
        l_limit->set_start_epoch_msec(l_cur_time_ms);
        l_limit->set_end_epoch_msec(l_cur_time_ms + l_e_duration_s*1000);
        // -------------------------------------------------
        // set
        // -------------------------------------------------
        *ao_cfg = l_cfg;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details  run a limit operator on some data
//! \l_retval number of entries added to ao_match_list
//!           -1 on failure
//! \param    TODO
//! ----------------------------------------------------------------------------
int32_t rl_run_op(bool &ao_matched,
                  const waflz_pb::op_t &a_op,
                  const char *a_data,
                  uint32_t a_len,
                  bool a_case_insensitive)
{
        // assume operator is STREQ
        ao_matched = false;
        waflz_pb::op_t_type_t l_op_type = waflz_pb::op_t_type_t_STREQ;
        if(a_op.has_type())
        {
                // operator type actually provided
                l_op_type = a_op.type();
        }
        switch (l_op_type)
        {
        // -------------------------------------------------
        // RX (regex)
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_RX:
        {
                // -----------------------------------------
                // get regex
                // -----------------------------------------
                if(!a_op.has__reserved_1())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                regex *l_rx = (regex *)(a_op._reserved_1());
                if(!l_rx)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // match?
                // -----------------------------------------
                //TRC_ALL("RX[%p]: %s == %.*s\n", l_rx, l_rx->get_regex_string().c_str(), (int)a_len, a_data);
                int l_s;
                l_s = l_rx->compare(a_data, a_len);
                // if failed to match
                if(l_s < 0)
                {
                        break;
                }
                ao_matched = true;
                break;
        }
        // -------------------------------------------------
        // STREQ
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_STREQ:
        {
                const std::string &l_op_match = a_op.value();
                uint32_t l_len = l_op_match.length();
                if(l_len != a_len)
                {
                        break;
                }
                int l_cmp = 0;
                if(a_case_insensitive)
                {
                        l_cmp = strncasecmp(l_op_match.c_str(), a_data, l_len);
                }
                else
                {
                        l_cmp = strncmp(l_op_match.c_str(), a_data, l_len);
                }
                if(l_cmp == 0)
                {
                        // matched
                        ao_matched = true;
                        break;
                }
                //TRACE("Got data: '%.*s' and match '%s'", SUBBUF_FORMAT(a_data), l_op_match.c_str());
                break;
        }
        // -------------------------------------------------
        // GLOB (glob -wildcard match)
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_GLOB:
        {
                int l_flags = FNM_NOESCAPE;
                if(a_case_insensitive)
                {
                        l_flags |= FNM_CASEFOLD;
                }
                int l_cmp;
                const std::string &l_op_match = a_op.value();
                l_cmp = fnmatch(l_op_match.c_str(), a_data, l_flags);
                if(l_cmp == 0)
                {
                        // matched
                        ao_matched = true;
                }
                break;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_IPMATCH:
        {
                // -----------------------------------------
                // get regex
                // -----------------------------------------
                if(!a_op.has__reserved_1())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                nms *l_nms = (nms *)(a_op._reserved_1());
                if(!l_nms)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // match?
                // -----------------------------------------
                int32_t l_s;
                l_s = l_nms->contains(ao_matched, a_data, a_len);
                // if failed to match
                if(l_s < 0)
                {
                        break;
                }
                break;
        }
        // -------------------------------------------------
        // Exact Match list (EM)
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_EM:
        {
                // -----------------------------------------
                // get str set
                // -----------------------------------------
                if(!a_op.has__reserved_1())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // case insensitive
                // -----------------------------------------
                if(a_op.is_case_insensitive())
                {
                        data_case_i_set_t *l_ds = (data_case_i_set_t *)(a_op._reserved_1());
                        if(!l_ds)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // match?
                        // ---------------------------------
                        data_t l_d;
                        l_d.m_data = a_data;
                        l_d.m_len = a_len;
                        data_case_i_set_t::const_iterator i_d = l_ds->find(l_d);
                        if((i_d != l_ds->end()) &&
                           (i_d->m_len == l_d.m_len))
                        {
                                ao_matched = true;
                        }
                }
                // -----------------------------------------
                // case sensitive
                // -----------------------------------------
                else
                {
                       data_set_t *l_ds = (data_set_t *)(a_op._reserved_1());
                        if(!l_ds)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // match?
                        // ---------------------------------
                        data_t l_d;
                        l_d.m_data = a_data;
                        l_d.m_len = a_len;
                        data_set_t::const_iterator i_d = l_ds->find(l_d);
                        if((i_d != l_ds->end()) &&
                           (i_d->m_len == l_d.m_len))
                        {
                                ao_matched = true;
                        }
                }
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                // do nothing...
                return WAFLZ_STATUS_OK;
        }
        }
        if(a_op.is_negated())
        {
                // negate value
                ao_matched = !ao_matched;
        }
        // -------------------------------------------------
        // TODO -push matches???
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details check if request "in scope"
//! \return  true if in scope
//!          false if not in scope
//! \param   a_scope TODO
//! \param   a_ctx   TODO
//! ----------------------------------------------------------------------------
int32_t in_scope(bool &ao_match,
                 const waflz_pb::scope &a_scope,
                 rqst_ctx *a_ctx)
{
        ao_match = false;
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // host
        // -------------------------------------------------
        if(a_scope.has_host() &&
           a_scope.host().has_type() &&
           (a_scope.host().has_value() ||
            a_scope.host().values_size()))
        {
                const data_t &l_d = a_ctx->m_host;
                if(!l_d.m_data ||
                   !l_d.m_len)
                {
                        return WAFLZ_STATUS_OK;
                }
                bool l_matched = false;
                int32_t l_s;
                l_s = rl_run_op(l_matched,
                                a_scope.host(),
                                l_d.m_data,
                                l_d.m_len,
                                true);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_matched)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // path
        // -------------------------------------------------
        if(a_scope.has_path() &&
           a_scope.path().has_type() &&
           (a_scope.path().has_value() ||
            a_scope.path().values_size()))
        {
                data_t l_d = a_ctx->m_uri;
                if(!l_d.m_data ||
                   !l_d.m_len)
                {
                        return WAFLZ_STATUS_OK;
                }
                // use length w/o q string
                // use length w/o q string
                if(a_ctx->m_uri_path_len)
                {
                        l_d.m_len = a_ctx->m_uri_path_len;
                }
                bool l_matched = false;
                int32_t l_s;
                l_s = rl_run_op(l_matched,
                                a_scope.path(),
                                l_d.m_data,
                                l_d.m_len,
                                true);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_matched)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        ao_match = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details C binding for third party lib to create a scopes obj
//! \return  a scopes object
//! \param   a_engine: waflz engine object
//! ----------------------------------------------------------------------------
extern "C" scopes *create_scopes(engine *a_engine)
{
        ns_waflz::kv_db* l_db = NULL;
        ns_waflz::challenge *l_c = NULL;
        return new scopes(*a_engine, *l_db, *l_c);
}
//! ----------------------------------------------------------------------------
//! \details C binding for third party lib to load a scopes config in json frmt
//! \return  0 on success
//!          -1 on failure
//! \param   a_scope: scopes object
//! \param   a_buf: a char pointer to contents of a scopes config file
//! \param   a_len: length of a_buf
//! \param   a_conf_dir: the location of acl, waf, rules config
//!          which are part of a scope config
//! ----------------------------------------------------------------------------
extern "C" int32_t load_config(scopes *a_scope, const char *a_buf, uint32_t a_len, const char *a_conf_dir)
{
        std::string l_conf_dir(a_conf_dir);
        return a_scope->load(a_buf, a_len, l_conf_dir);
}
//! ----------------------------------------------------------------------------
//! \details C binding for third party lib to process a request through waflz
//! \return  0 on success
//!          -1 on failure
//! \param   a_scope: scopes object
//! \param   ao_ctx: void pointer of the request ctx of the calling http library
//! \param   a_rqst_ctx: object of waflz rqst_ctx class, which holds all 
//!          the pieces of a http request
//! \param   a_callbacks: callback struct which tells rqst_ctx where to get 
//!          the peices of a http request from the given ao_ctx
//! \param   ao_event: event details, if there was an action taken by waflz
//! ----------------------------------------------------------------------------
extern "C" int32_t process_waflz(scopes *a_scope, void *ao_ctx, rqst_ctx *a_rqst_ctx, const rqst_ctx_callbacks *a_callbacks, char **ao_event)
{
        return a_scope->process_request_plugin(ao_event, ao_ctx, a_callbacks, &a_rqst_ctx);
}
//! ----------------------------------------------------------------------------
//! \details C binding for third party lib to do a graceful cleanup of scopes object
//! \return  0: success
//! \param   a_scope: scopes object
//! ----------------------------------------------------------------------------
extern "C" int32_t cleanup_scopes(scopes *a_scopes)
{
        if(a_scopes)
        {
                delete a_scopes;
                a_scopes = NULL;
        }
        return WAFLZ_STATUS_OK;
}
}
