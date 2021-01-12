//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _BOTS_H_
#define _BOTS_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include <string>
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
class sec_config_t;
class enforcement;
class event;
class request_info;
}
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class engine;
class waf;
class rqst_ctx;
class challenge;
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
class bots
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        bots(engine &a_engine, challenge& a_challenge);
        ~bots();
        int32_t process(waflz_pb::event **ao_event, void *a_ctx, const waflz_pb::enforcement **a_scope_enf, rqst_ctx **ao_rqst_ctx = NULL);
        int32_t load_file(const char *a_buf, uint32_t a_buf_len);
        int32_t load(void* a_js);
        //: ------------------------------------------------
        //: \details Get last error message string
        //: \return  last error message (in buffer)
        //: ------------------------------------------------
        const char *get_err_msg(void) { return m_err_msg; }
        waf *get_waf(void) { return m_waf; }
        const std::string& get_id(void) { return m_id; };
        const std::string& get_cust_id(void) { return m_cust_id; };
        const std::string& get_name(void) { return m_name; };
        const waflz_pb::sec_config_t* get_pb(void);
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        //DISALLOW_DEFAULT_CTOR(profile);
        // disallow copy/assign
        bots(const bots &);
        bots& operator=(const bots &);
        int32_t init(void);
        int32_t validate(void);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine &m_engine;
        // -------------------------------------------------
        // engines...
        // -------------------------------------------------
        waf *m_waf;
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
