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
#include "sx_scopes.h"
#include "waflz/engine.h"
#include "waflz/rqst_ctx.h"
#include "waflz/string_util.h"
#include "is2/support/trace.h"
#include "is2/support/nbq.h"
#include "is2/support/ndebug.h"
#include "is2/srvr/api_resp.h"
#include "is2/srvr/srvr.h"
#include "jspb/jspb.h"
#include "support/file_util.h"
#include "event.pb.h"
#include "profile.pb.h"
#include "limit.pb.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef STATUS_OK
  #define STATUS_OK 0
#endif
#ifndef STATUS_ERROR
  #define STATUS_ERROR -1
#endif
#define _WAFLZ_SERVER_SCOPES_ID "waf-scopes-id"
namespace ns_waflz_server {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
sx_scopes::sx_scopes(ns_waflz::engine& a_engine,
                     ns_waflz::kv_db &a_db,
                     ns_waflz::challenge& a_challenge):
        m_bg_load(false),
        m_is_rand(false),
        m_engine(a_engine),
        m_db(a_db),
        m_challenge(a_challenge),
        m_conf_dir(),
        m_scopes_configs(NULL),
        m_update_scopes_h(NULL),
        m_update_acl_h(NULL),
        m_update_rules_h(NULL),
        m_update_bots_h(NULL),
        m_update_profile_h(NULL),
        m_update_limit_h(NULL)
{

}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
sx_scopes::~sx_scopes(void)
{
        if(m_update_scopes_h) { delete m_update_scopes_h; m_update_scopes_h = NULL; }
        if(m_update_acl_h) { delete m_update_acl_h; m_update_acl_h = NULL; }
        if(m_update_rules_h) { delete m_update_rules_h; m_update_rules_h = NULL; }
        if(m_update_bots_h) { delete m_update_bots_h; m_update_bots_h = NULL; }
        if(m_update_profile_h) { delete m_update_profile_h; m_update_profile_h = NULL; }
        if(m_update_limit_h) {delete m_update_limit_h; m_update_limit_h = NULL; }
        if(m_scopes_configs) { delete m_scopes_configs; m_scopes_configs = NULL; }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t sx_scopes::init(void)
{
        // -------------------------------------------------
        // create scope configs
        // -------------------------------------------------
        m_scopes_configs = new ns_waflz::scopes_configs(m_engine, m_db, m_challenge, false);
        m_scopes_configs->set_conf_dir(m_conf_dir);
        // -------------------------------------------------
        // enable locking
        // -------------------------------------------------
        m_scopes_configs->set_locking(true);
        // -------------------------------------------------
        // get config type -file or directory
        // -------------------------------------------------
        bool l_is_dir_flag = false;
        struct stat l_stat;
        int32_t l_s;
        l_s = stat(m_config.c_str(), &l_stat);
        if(l_s != 0)
        {
                NDBG_PRINT("error performing stat on directory: %s.  Reason: %s\n", m_config.c_str(), strerror(errno));
                return STATUS_ERROR;
        }
        // Check if is directory
        if(l_stat.st_mode & S_IFDIR)
        {
                l_is_dir_flag = true;
        }
        // -------------------------------------------------
        // load scopes dir
        // -------------------------------------------------
        if(l_is_dir_flag)
        {
                // -----------------------------------------
                // recurse through directory
                // -----------------------------------------
                //NDBG_PRINT("scopes configs dir: %s\n", m_config.c_str());
                l_s = m_scopes_configs->load_dir(m_config.c_str(),
                                                 m_config.length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading config dir: %s. reason: %s\n", m_config.c_str(), m_scopes_configs->get_err_msg());
                        return STATUS_ERROR;
                }

        }
        // -------------------------------------------------
        // load single scopes file
        // -------------------------------------------------
        else
        {
                l_s = m_scopes_configs->load_file(m_config.c_str(), m_config.length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading config: %s. reason: %s\n", m_config.c_str(), m_scopes_configs->get_err_msg());
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // update end points
        // -------------------------------------------------
        // -------------------------------------------------
        // scopes
        // -------------------------------------------------
        m_update_scopes_h = new update_entity_h<ENTITY_TYPE_SCOPES>(m_scopes_configs, m_bg_load);
        m_lsnr->add_route("/update_scopes", m_update_scopes_h);
        // -------------------------------------------------
        // acl
        // -------------------------------------------------
        m_update_acl_h = new update_entity_h<ENTITY_TYPE_ACL>(m_scopes_configs, m_bg_load);
        m_lsnr->add_route("/update_acl", m_update_acl_h);
        // -------------------------------------------------
        // rules
        // -------------------------------------------------
        m_update_rules_h = new update_entity_h<ENTITY_TYPE_RULES>(m_scopes_configs, m_bg_load);
        m_lsnr->add_route("/update_rules", m_update_rules_h);
        // -------------------------------------------------
        // bots
        // -------------------------------------------------
        m_update_bots_h = new update_entity_h<ENTITY_TYPE_BOTS>(m_scopes_configs, m_bg_load);
        m_lsnr->add_route("/update_bots", m_update_bots_h);
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
        m_update_profile_h = new update_entity_h<ENTITY_TYPE_PROFILE>(m_scopes_configs, m_bg_load);
        m_lsnr->add_route("/update_profile", m_update_profile_h);
        // -------------------------------------------------
        // limit
        // -------------------------------------------------
        m_update_limit_h = new update_entity_h<ENTITY_TYPE_LIMIT>(m_scopes_configs, m_bg_load);
        m_lsnr->add_route("/update_limit", m_update_limit_h);
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
ns_is2::h_resp_t sx_scopes::handle_rqst(waflz_pb::enforcement **ao_enf,
                                        ns_waflz::rqst_ctx **ao_ctx,
                                        ns_is2::session &a_session,
                                        ns_is2::rqst &a_rqst,
                                        const ns_is2::url_pmap_t &a_url_pmap)
{
        if(ao_enf) { *ao_enf = NULL;}
        if(!m_scopes_configs)
        {
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // events
        // -------------------------------------------------
        int32_t l_s;
        waflz_pb::event *l_event_prod = NULL;
        waflz_pb::event *l_event_audit = NULL;
        ns_waflz::rqst_ctx *l_ctx  = NULL;
        m_resp = "{\"status\": \"ok\"}";
        uint64_t l_id = 0;
        // -------------------------------------------------
        // get id from header if exists
        // -------------------------------------------------
        const ns_is2::mutable_data_map_list_t& l_headers(a_rqst.get_header_map());
        ns_is2::mutable_data_t i_hdr;
        if(ns_is2::find_first(i_hdr, l_headers, _WAFLZ_SERVER_SCOPES_ID, sizeof(_WAFLZ_SERVER_SCOPES_ID)))
        {
                std::string l_hex;
                l_hex.assign(i_hdr.m_data, i_hdr.m_len);
                l_s = ns_waflz::convert_hex_to_uint(l_id, l_hex.c_str());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("an provided is not a provided hex\n");
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
        }
        // -------------------------------------------------
        // pick rand if id empty
        // -------------------------------------------------
        if(!l_id &&
           m_is_rand)
        {
                m_scopes_configs->get_rand_id(l_id);
        }
        // -------------------------------------------------
        // get first
        // -------------------------------------------------
        else if(!l_id)
        {
                m_scopes_configs->get_first_id(l_id);
        }
        // -------------------------------------------------
        // if no id -error
        // -------------------------------------------------
        if(!l_id)
        {
                if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                if(l_event_prod) { delete l_event_prod; l_event_prod = NULL; }
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        l_s = m_scopes_configs->process(ao_enf,
                                        &l_event_audit,
                                        &l_event_prod,
                                        &a_session,
                                        l_id,
                                        ns_waflz::PART_MK_ALL,
                                        m_callbacks,
                                        &l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error processing config. reason: %s\n",
                            m_scopes_configs->get_err_msg());
                if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                if(l_event_prod) { delete l_event_prod; l_event_prod = NULL; }
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // YOU ARE HERE
        if(l_ctx &&
           l_ctx->m_limit)
        {
                waflz_pb::alert* l_alert = NULL;
                m_scopes_configs->generate_alert(&l_alert, l_ctx, l_id);
                //uncomment to print rl alert
                NDBG_PRINT("rl event: %s", l_alert->DebugString().c_str());
                if(l_alert) { delete l_alert; l_alert = NULL; }
        }
        // -------------------------------------------------
        // *************************************************
        //                R E S P O N S E
        // *************************************************
        // -------------------------------------------------
        std::string l_event_str = "{}";
        // -------------------------------------------------
        // for instances create string with both...
        // -------------------------------------------------
        rapidjson::Document l_event_prod_json;
        rapidjson::Document l_event_audit_json;
        if(l_event_audit)
        {
                //NDBG_PRINT(" audit event %s", l_event_audit->DebugString().c_str());
                l_s = ns_waflz::convert_to_json(l_event_audit_json, *l_event_audit);
                if(l_s != JSPB_OK)
                {
                        NDBG_PRINT("error performing convert_to_json.\n");
                        if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                        if(l_event_prod) { delete l_event_prod; l_event_prod = NULL; }
                        if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
        }
        if(l_event_prod)
        {
                //NDBG_PRINT(" prod event %s",l_event_prod->DebugString().c_str());
                l_s = ns_waflz::convert_to_json(l_event_prod_json, *l_event_prod);
                if(l_s != JSPB_OK)
                {
                        NDBG_PRINT("error performing convert_to_json.\n");
                        if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                        if(l_event_prod) { delete l_event_prod; l_event_prod = NULL; }
                        if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
        }
        // -------------------------------------------------
        // create resp...
        // -------------------------------------------------
        rapidjson::Document l_js_doc;
        l_js_doc.SetObject();
        rapidjson::Document::AllocatorType& l_js_allocator = l_js_doc.GetAllocator();
        l_js_doc.AddMember("audit_profile", l_event_audit_json, l_js_allocator);
        l_js_doc.AddMember("prod_profile",  l_event_prod_json, l_js_allocator);
        rapidjson::StringBuffer l_strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> l_js_writer(l_strbuf);
        l_js_doc.Accept(l_js_writer);
        m_resp.assign(l_strbuf.GetString(), l_strbuf.GetSize());
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
        if(l_event_prod) { delete l_event_prod; l_event_prod = NULL; }
        if(ao_ctx)
        {
                *ao_ctx = l_ctx;
        }
        else if(l_ctx)
        {
                delete l_ctx; l_ctx = NULL;
        }
        return ns_is2::H_RESP_DONE;
}
}
