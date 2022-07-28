//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _BOT_MANAGER_H_
#define _BOT_MANAGER_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/city.h"
#include <string>
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
class bot_manager;
class event;
class enforcement;
}
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class bots;
class challenge;
class rqst_ctx;
class engine;
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
class bot_manager
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        bot_manager(engine &a_engine, challenge& a_challenge);
        ~bot_manager();
        int32_t process(waflz_pb::event **ao_event,
                        const waflz_pb::enforcement** ao_enf,
                        void *a_ctx,
                        rqst_ctx **ao_rqst_ctx = NULL);
        int32_t load(const char *a_buf, uint32_t a_buf_len, const std::string& a_conf_dir_path);
        int32_t load(void* a_js, const std::string& a_conf_dir_path);
        //: ------------------------------------------------
        //: \details Get last error message string
        //: \return  last error message (in buffer)
        //: ------------------------------------------------
        const char *get_err_msg(void) { return m_err_msg; }
        const std::string& get_id(void) { return m_id; };
        const std::string& get_cust_id(void) { return m_cust_id; };
        const std::string& get_name(void) { return m_name; };
        const waflz_pb::bot_manager* get_pb(void) { return m_pb; };
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        //DISALLOW_DEFAULT_CTOR(bot_manager);
        // disallow copy/assign
        bot_manager(const bot_manager &);
        bot_manager& operator=(const bot_manager &);
        int32_t init(const std::string& a_conf_dir_path);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        char m_err_msg[WAFLZ_ERR_LEN];
        waflz_pb::bot_manager* m_pb;
        //TODO: To allow mutiple bot rules,
        // change this to a map of <bots_id, *bots> for fast path
        // updates and use reserved field in proto to access
        // corresponding bots object during process().
        ns_waflz::bots *m_bots;
        engine &m_engine;
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        std::string m_id;
        std::string m_cust_id;
        std::string m_name;
        // -------------------------------------------------
        // bot challenge
        // -------------------------------------------------
        challenge& m_challenge;
};
}
#endif
