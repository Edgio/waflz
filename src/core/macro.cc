//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
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
#include "waflz/def.h"
#include "support/ndebug.h"
#include "core/macro.h"
#include "core/var.h"
#include "op/regex.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define MACRO_EXP_REGEX "%{\\w*..\\w*}"
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define STRCASECMP(_str, _match) (strcasecmp(_str.c_str(), _match) == 0)
#define STRCASECMP_KV(_match) (strcasecmp(i_k->m_key, _match.c_str()) == 0)
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details get var
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
static int32_t get_var(std::string &ao_var,
                       waflz_pb::variable_t_type_t a_type,
                       rqst_ctx *a_ctx)
{
        get_var_t l_get_var = NULL;
        l_get_var = get_var_cb(a_type);
        if(!l_get_var)
        {
                NDBG_PRINT("cb not implemented");
                return WAFLZ_STATUS_ERROR;
        }
        uint32_t l_var_count = 0;
        const_arg_list_t l_d_list;
        waflz_pb::variable_t l_var;
        int32_t l_s = WAFLZ_STATUS_OK;
        // -------------------------------------------------
        // get var
        // -------------------------------------------------
        l_s = l_get_var(l_d_list, l_var_count, l_var, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract the data from list
        // -------------------------------------------------
        ao_var.clear();
        for(const_arg_list_t::const_iterator i_v = l_d_list.begin();
            i_v != l_d_list.end();
            ++i_v)
        {
                ao_var.append(i_v->m_val, i_v->m_val_len);
                ao_var.append(" ");
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Expand the str of the form %{MATCHED_VAR_NAME}
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
static int32_t expand(std::string &ao_exp,
                      const std::string& a_str,
                      rqst_ctx *a_ctx,
                      resp_ctx *a_res_ctx)
{
        // -------------------------------------------------
        // Should always be either request ctx or resp ctx
        // -------------------------------------------------
        if((!a_ctx && !a_res_ctx) ||
           (a_ctx && a_res_ctx))
        {
                return WAFLZ_STATUS_ERROR;
        }
        size_t l_pos = a_str.find("%{");
        // e.g %{MATCHED_VAR_NAME}
        if(l_pos == std::string::npos)
        {
                return WAFLZ_STATUS_ERROR;
        }
        size_t l_pos_end = a_str.find("}");
        if(l_pos_end == std::string::npos)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // MATCHED_VAR_NAME
        // -------------------------------------------------
        std::string l_var(a_str, (l_pos + 2), l_pos_end - (l_pos + 2));
        // Check if its a collection:
        // e.g %{tx.missing_header}
        size_t l_pos_col = l_var.find(".");
        if(l_pos_col == std::string::npos)
        {
                l_pos_col = l_var.find(":");
        }
        // -------------------------------------------------
        // not found
        // -------------------------------------------------
        if(l_pos_col == std::string::npos)
        {
                // -----------------------------------------
                // *****************************************
                //                 V A R S
                // *****************************************
                // -----------------------------------------
                if(a_ctx)
                {
                        // -----------------------------------------
                        // ARGS_COMBINED_SIZE
                        // -----------------------------------------
                        if(STRCASECMP(l_var, "ARGS_COMBINED_SIZE"))
                        {
                                int32_t l_s;
                                l_s = get_var(ao_exp, waflz_pb::variable_t_type_t_ARGS_COMBINED_SIZE, a_ctx);
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        return WAFLZ_STATUS_ERROR;
                                }
                                return WAFLZ_STATUS_OK;
                        }
                        // -----------------------------------------
                        // FILES_COMBINED_SIZE
                        // -----------------------------------------
                        if(STRCASECMP(l_var, "FILES_COMBINED_SIZE"))
                        {
                                int32_t l_s;
                                l_s = get_var(ao_exp, waflz_pb::variable_t_type_t_FILES_COMBINED_SIZE, a_ctx);
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        return WAFLZ_STATUS_ERROR;
                                }
                                return WAFLZ_STATUS_OK;
                        }
                        // -----------------------------------------
                        // *****************************************
                        //          C O L L E C T I O N S
                        // *****************************************
                        // -----------------------------------------
#define _SET_FROM_STR(_name, _from) \
        if(STRCASECMP(l_var, _name)) { \
                ao_exp.assign(_from); \
                return WAFLZ_STATUS_OK; \
        }
                        _SET_FROM_STR("MATCHED_VAR", a_ctx->m_cx_matched_var)
                        _SET_FROM_STR("MATCHED_VAR_NAME", a_ctx->m_cx_matched_var_name)
                        // -----------------------------------------
                        // *****************************************
                        //              C O N T E X T
                        // *****************************************
                        // -----------------------------------------
#define _SET_FROM_VAR(_name, _from) \
        if(STRCASECMP(l_var, _name)) { \
                ao_exp.assign(_from.m_data, _from.m_len); \
                return WAFLZ_STATUS_OK; \
        }
                        _SET_FROM_VAR("QUERY_STRING", a_ctx->m_query_str)
                        _SET_FROM_VAR("REMOTE_ADDR", a_ctx->m_src_addr)
                        _SET_FROM_VAR("REQUEST_PROTOCOL", a_ctx->m_protocol)
                        _SET_FROM_VAR("REQUEST_URI", a_ctx->m_uri)
                        _SET_FROM_VAR("REQUEST_LINE", a_ctx->m_line)
                        _SET_FROM_VAR("REQUEST_BASENAME", a_ctx->m_base)
                        _SET_FROM_VAR("REQUEST_METHOD", a_ctx->m_method)
                        else
                        {
                                //NDBG_PRINT("Variable not supported:: %s", l_var.c_str());
                        }
                }
                if(a_res_ctx)
                {
                        // -----------------------------------------
                        // *****************************************
                        //          C O L L E C T I O N S
                        // *****************************************
                        // -----------------------------------------
#define _SET_R_FROM_STR(_name, _from) \
        if(STRCASECMP(l_var, _name)) { \
                ao_exp.assign(_from); \
                return WAFLZ_STATUS_OK; \
        }
                        _SET_R_FROM_STR("MATCHED_VAR", a_res_ctx->m_cx_matched_var)
                        _SET_R_FROM_STR("MATCHED_VAR_NAME", a_res_ctx->m_cx_matched_var_name)
                        else
                        {
                                //NDBG_PRINT("Variable not supported:: %s", l_var.c_str());
                        }
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // scope var
        // -------------------------------------------------
        // -------------------------------------------------
        // Get the value of variable
        // TX or IP or GEO col map
        // -------------------------------------------------
        std::string l_scope = std::string(l_var, 0, l_pos_col);
        std::string l_cx_var = std::string(l_var, l_pos_col + 1, l_var.length() - (l_pos_col + 1));
        //NDBG_PRINT("%s.%s\n", l_scope.c_str(), l_cx_var.c_str());
        if(a_ctx)
        {
                // -------------------------------------------------
                // TX
                // -------------------------------------------------
                if(STRCASECMP(l_scope, "TX"))
                {
                        cx_map_t::const_iterator i_t = a_ctx->m_cx_tx_map.find(l_cx_var);
                        if(i_t != a_ctx->m_cx_tx_map.end())
                        {
                                ao_exp = i_t->second;
                        }
                        return WAFLZ_STATUS_OK;
                }
                // -------------------------------------------------
                // RULE
                // -------------------------------------------------
                if(STRCASECMP(l_scope, "RULE"))
                {
                        data_t l_d;
                        l_d.m_data = l_cx_var.c_str();
                        l_d.m_len = l_cx_var.length();
                        data_map_t::const_iterator i_t = a_ctx->m_cx_rule_map.find(l_d);
                        if(i_t != a_ctx->m_cx_rule_map.end())
                        {
                                ao_exp.assign(i_t->second.m_data, i_t->second.m_len);
                        }
                        return WAFLZ_STATUS_OK;
                }
                // -------------------------------------------------
                // REQUEST_HEADERS
                // -------------------------------------------------
                else if(STRCASECMP(l_scope, "REQUEST_HEADERS"))
                {
                        // -----------------------------------------
                        // get var...
                        // -----------------------------------------
                        get_var_t l_get_var = NULL;
                        l_get_var = get_var_cb(waflz_pb::variable_t_type_t_REQUEST_HEADERS);
                        if(!l_get_var)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        // -----------------------------------------
                        // extract list of data
                        // -----------------------------------------
                        const_arg_list_t l_dl;
                        uint32_t l_vc;
                        int32_t l_s;
                        waflz_pb::variable_t l_vr;
                        l_vr.add_match()->set_value(l_cx_var);
                        l_s = l_get_var(l_dl, l_vc, l_vr, a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(!l_dl.size())
                        {
                                return WAFLZ_STATUS_OK;
                        }
                        const_arg_list_t::const_iterator i_h = l_dl.begin();
                        ao_exp.assign(i_h->m_val, i_h->m_val_len);
                        return WAFLZ_STATUS_OK;
                }
        }
        else if(a_res_ctx)
        {
                // -------------------------------------------------
                // TX
                // -------------------------------------------------
                if(STRCASECMP(l_scope, "TX"))
                {
                        cx_map_t::const_iterator i_t = a_res_ctx->m_cx_tx_map.find(l_cx_var);
                        if(i_t != a_res_ctx->m_cx_tx_map.end())
                        {
                                ao_exp = i_t->second;
                        }
                        return WAFLZ_STATUS_OK;
                }
                // -------------------------------------------------
                // RULE
                // -------------------------------------------------
                if(STRCASECMP(l_scope, "RULE"))
                {
                        data_t l_d;
                        l_d.m_data = l_cx_var.c_str();
                        l_d.m_len = l_cx_var.length();
                        data_map_t::const_iterator i_t = a_res_ctx->m_cx_rule_map.find(l_d);
                        if(i_t != a_res_ctx->m_cx_rule_map.end())
                        {
                                ao_exp.assign(i_t->second.m_data, i_t->second.m_len);
                        }
                        return WAFLZ_STATUS_OK;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
macro::macro():
        m_regex()
{
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t macro::init()
{
        int32_t l_s;
        l_s = m_regex.init(MACRO_EXP_REGEX, strlen(MACRO_EXP_REGEX));
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details check if has
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
bool macro::has(const std::string &a_str)
{
        int32_t l_s;
        l_s = m_regex.compare(a_str.c_str(), a_str.length(), NULL);
        if(l_s >= 0)
        {
               return true;
        }
        return false;
}
//! ----------------------------------------------------------------------------
//! \details Expand the variable of the form %{MATCHED_VAR_NAME}
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t macro::operator ()(std::string &ao_exp,
                           const std::string& a_str,
                           rqst_ctx *a_ctx,
                           resp_ctx *a_res_ctx)
{
        if(!a_ctx && !a_res_ctx)
        {
            return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // find matches...
        // -------------------------------------------------
        //NDBG_PRINT("checking string: %s\n", a_str.c_str());
        ao_exp.clear();
        data_list_t l_data;
        int32_t l_s;
        l_s = m_regex.compare_all(a_str.c_str(), a_str.length(), &l_data);
        if(l_s <= 0)
        {
                ao_exp = a_str;
                return WAFLZ_STATUS_OK;
        }
        const char * l_l_ptr = a_str.c_str();
        // -------------------------------------------------
        // for each match...
        // -------------------------------------------------
        for(data_list_t::iterator i_t = l_data.begin();
            i_t != l_data.end();
            ++i_t)
        {
                const char *l_m_ptr = (*i_t).m_data;
                uint32_t l_m_len = (*i_t).m_len;
                // TODO -zero copy version???
                std::string l_e_v;
                l_e_v.assign(l_m_ptr, l_m_len);
                // -----------------------------------------
                // append all non macro chars...
                // -----------------------------------------
                while(l_l_ptr < l_m_ptr)
                {
                        ao_exp.append(l_l_ptr, 1);
                        ++l_l_ptr;
                }
                // -----------------------------------------
                // get expansion
                // -----------------------------------------
                int32_t l_s;
                std::string l_str;
                //NDBG_PRINT("expand:   %s\n", l_e_v.c_str());
                l_s = expand(l_str, l_e_v, a_ctx, a_res_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                //NDBG_PRINT("expanded: %s\n", l_str.c_str());
                // -----------------------------------------
                // append
                // -----------------------------------------
                ao_exp += l_str;
                l_l_ptr += l_m_len;
        }
        if(strlen(l_l_ptr))
        {
                ao_exp.append(l_l_ptr, strlen(l_l_ptr));
        }
        //NDBG_PRINT("expansion: %s\n", ao_exp.c_str());
        return WAFLZ_STATUS_OK;
}
}
