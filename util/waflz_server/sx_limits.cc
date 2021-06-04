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
#include "sx_limits.h"
#include "is2/support/ndebug.h"
#include "waflz/redis_db.h"
#include "waflz/configs.h"
#include "waflz/config.h"
#include "waflz/geoip2_mmdb.h"
#include "waflz/challenge.h"
#include "support/file_util.h"
#include "action.pb.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef STATUS_OK
  #define STATUS_OK 0
#endif
#ifndef STATUS_ERROR
  #define STATUS_ERROR -1
#endif
namespace ns_waflz_server {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
sx_limits::sx_limits(ns_waflz::kv_db &a_db):
        m_configs(NULL),
        m_cust_id(0),
        m_db(a_db)
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
sx_limits::~sx_limits(void)
{
        if(m_configs) { delete m_configs; m_configs = NULL; }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t sx_limits::init(void)
{
        char *l_buf;
        uint32_t l_buf_len;
        int32_t l_s;
        // -------------------------------------------------
        // load file
        // -------------------------------------------------
        //NDBG_PRINT("reading file: %s\n", l_profile_file.c_str());
        l_s = ns_waflz::read_file(m_config.c_str(), &l_buf, l_buf_len);
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error read_file: %s\n", m_config.c_str());
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // load config
        // -------------------------------------------------
        m_configs = new ns_waflz::configs(m_db);
        l_s = m_configs->load(l_buf, l_buf_len);
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error performing load: Reason: %s\n", m_configs->get_err_msg());
                if(m_configs) { delete m_configs; m_configs = NULL;}
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return STATUS_ERROR;
        }
        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
        // -------------------------------------------------
        // get first id
        // -------------------------------------------------
        uint64_t l_first_id;
        l_s = m_configs->get_first_id(l_first_id);
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error performing get_first_id: Reason: %s\n", m_configs->get_err_msg());
                if(m_configs) { delete m_configs; m_configs = NULL;}
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return STATUS_ERROR;
        }
        m_cust_id = l_first_id;
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
ns_is2::h_resp_t sx_limits::handle_rqst(waflz_pb::enforcement **ao_enf,
                                       ns_waflz::rqst_ctx **ao_ctx,
                                       ns_is2::session &a_session,
                                       ns_is2::rqst &a_rqst,
                                       const ns_is2::url_pmap_t &a_url_pmap)
{
        if(ao_enf) { *ao_enf = NULL;}
        m_resp = "{\"status\": \"ok\"}";
        if(!m_configs)
        {
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        int32_t l_s;
        ns_waflz::rqst_ctx *l_ctx = NULL;
        // -------------------------------------------------
        // get coord
        // -------------------------------------------------
        ns_waflz::config* l_config = NULL;
        l_s = m_configs->get_config(&l_config, m_cust_id);
        if((l_s != STATUS_OK) ||
           (!l_config))
        {
                NDBG_PRINT("error performing get_coordinator_config.  Reason: %s\n", m_configs->get_err_msg());
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // init rqst processing
        // -------------------------------------------------
        l_ctx = new ns_waflz::rqst_ctx((void *)&a_session, 0, m_callbacks, false, false);
        ns_waflz::geoip2_mmdb l_geoip2_mmdb;
        l_s = l_ctx->init_phase_1(l_geoip2_mmdb);
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error performing init_phase_1.\n");
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        const waflz_pb::enforcement *l_enf = NULL;
        const waflz_pb::limit *l_limit = NULL;
        l_s = l_config->process(&l_enf,
                                &l_limit,
                                l_ctx);
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error performing config process.  Reason: %s\n", l_config->get_err_msg());
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // create enforcement copy...
        // -------------------------------------------------
        if(l_enf)
        {
                *ao_enf = new waflz_pb::enforcement();
                (*ao_enf)->CopyFrom(*l_enf);
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
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
