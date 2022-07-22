//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
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
#include "waflz/bot_manager.h"
#include "waflz/bots.h"
#include "waflz/engine.h"
#include "waflz/challenge.h"
#include "jspb/jspb.h"
#include "action.pb.h"
#include "event.pb.h"
#include "bot_manager.pb.h"
#include "support/ndebug.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _CONFIG_PROFILE_MAX_SIZE (1<<20)
namespace ns_waflz {
//! -----------------
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
bot_manager::bot_manager(engine &a_engine, challenge& a_challenge):
        m_init(false),
        m_err_msg(),
        m_pb(NULL),
        m_bots(NULL),
        m_engine(a_engine),
        m_id("__na__"),
        m_cust_id("__na__"),
        m_name("__na__"),
        m_challenge(a_challenge)
{
}
//! ----------------------------------------------------------------------------
//! \details dtor
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
bot_manager::~bot_manager()
{
        if(m_bots) { delete m_bots; m_bots = NULL; }
}
//! ----------------------------------------------------------------------------
//! \details load using file path. called during init and reloads
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t bot_manager::load(const char *a_buf, uint32_t a_buf_len, const std::string& a_conf_dir_path)
{
        int32_t l_s;
        if(a_buf_len > _CONFIG_PROFILE_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                             a_buf_len,
                             _CONFIG_PROFILE_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        if(m_pb)
        {
            delete m_pb; 
            m_pb = NULL;
        }
        m_pb = new waflz_pb::bot_manager();
        // -------------------------------------------------
        // load from json
        // -------------------------------------------------
        l_s = update_from_json(*m_pb, a_buf, a_buf_len);
        if (l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = init(a_conf_dir_path);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details load using json object- this gets called during fast path
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t bot_manager::load(void* a_js, const std::string& a_conf_dir_path)
{
        const rapidjson::Document &l_js = *((rapidjson::Document *)a_js);
        int32_t l_s;
        if (m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        m_pb = new waflz_pb::bot_manager();
        l_s = update_from_json(*m_pb, l_js);
        if (l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        l_s = init(a_conf_dir_path);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;

}
//! ----------------------------------------------------------------------------
//! \details Update fields from bot manager proto
//! \return  waflz status
//! \param   
//! -----------------------------------------------------------------------------
int32_t bot_manager::init(const std::string& a_conf_dir_path)
{
        int32_t l_s;
        if(m_init)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        m_id = m_pb->id();
        m_cust_id = m_pb->customer_id();
        m_name = m_pb->name();
        // -------------------------------------------------
        // make bots obj
        // -------------------------------------------------
        if ( m_pb->has_bots_prod_id())
        {
            std::string l_path;
            l_path = a_conf_dir_path + "/bots/" + m_cust_id + "-" + m_pb->bots_prod_id() +".bots.json";
            bots* l_bots = new bots(m_engine, m_challenge);
            l_s = l_bots->load_file(l_path.c_str(), l_path.length());
            if (l_s != WAFLZ_STATUS_OK)
            {
                    WAFLZ_PERROR(m_err_msg, "error loading conf file-reason: %.*s",
                                 WAFLZ_ERR_REASON_LEN,
                                 l_bots->get_err_msg());
                    if (l_bots) { delete l_bots; l_bots = NULL;}
                    return WAFLZ_STATUS_ERROR;
            }
            m_bots = l_bots;
        }
        // -------------------------------------------------
        // TODO: load known bot from proto into member vars
        // -------------------------------------------------
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details process bot mananger config
//! \return  waflz status
//! \param
//! -----------------------------------------------------------------------------
int32_t bot_manager::process(waflz_pb::event **ao_event,
                              const waflz_pb::enforcement** ao_enf,
                              void *a_ctx,
                              rqst_ctx **ao_rqst_ctx
                             )
{
        if (!ao_event)
        {
                WAFLZ_PERROR(m_err_msg, "ao_event == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        *ao_event = NULL;
        int32_t l_s;
        waflz_pb::event* l_event = NULL;
        const waflz_pb::enforcement* l_enf = NULL;
        // -------------------------------------------------
        // TODO : process known bot.
        // create l_event, l_enf and set ao_event
        // and ao_enf(goto done) if there is a match. if no match,
        // move on to process bot rules. 
        // -------------------------------------------------
        bool l_known_bot = false;
        bool l_spoof_bot = false;
        //l_s = process_known_bots(l_known_bot, l_spoof_bot)
        if(l_known_bot)
        {
                //frame l_enf object with known_bot_action)
                //frame l_event
                goto done;
        }
        if(l_spoof_bot)
        {
                //frame l_enf object with spoof_bot_action
                //frame l_event
                goto done;
        }
        // -------------------------------------------------
        // process bot rules
        // -------------------------------------------------
        if(!m_bots)
        {
                return WAFLZ_STATUS_OK;
        }
        l_s = m_bots->process(&l_event, a_ctx, ao_rqst_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", m_bots->get_err_msg());
                if(l_event) { delete l_event; l_event = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_event)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // bots-> process returns an event on rule match. 
        // if there is an event from bots->process,
        // get corresponding enforcement from bot manager config 
        // and set in *ao_enf for server to apply the enforcement.
        // if the enf type is browser challenge, do the
        // challenge verification before setting ao_enf
        // -------------------------------------------------
        l_enf = &(m_pb->bots_prod_action());
        if(!l_enf)
        {
            if(l_event) { delete l_event; l_event =  NULL; }
            return WAFLZ_STATUS_OK;
        }
        if(l_enf->enf_type() == waflz_pb::enforcement_type_t_BROWSER_CHALLENGE)
        {
                bool l_pass = false;
                // -------------------------
                // check cookie
                // verify browser challenge
                // -------------------------
                // default to valid for 10 min
                uint32_t l_valid_for_s = 600;
                if(l_enf->has_valid_for_sec())
                {
                        l_valid_for_s = l_enf->valid_for_sec();
                }
                int32_t l_s;
                l_s = m_challenge.verify(l_pass, l_valid_for_s, *ao_rqst_ctx, &l_event);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // do nothing -re-issue challenge. bye sending an event
                }
                if(l_pass)
                {
                        // Challenge passed. delete event.
                        // move on to next step in scope::process
                        if(l_event) { delete l_event; l_event =  NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_event->set_token_duration_sec(l_valid_for_s);
        }
        l_event->set_bots_config_id(m_bots->get_id());
        l_event->set_bots_config_name(m_bots->get_name());
done:
        // -------------------------------------------------
        // set event and enf
        // -------------------------------------------------
        l_event->set_bot_manager_config_id(m_id);
        *ao_event = l_event;
        *ao_enf = l_enf;
        if ((*ao_enf)->has_status())
        {
                (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
        }
        return WAFLZ_STATUS_OK;
}
}