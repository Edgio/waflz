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
#include "sx_limit.h"
#include "is2/support/ndebug.h"
#include "waflz/kycb_db.h"
#include "waflz/redis_db.h"
#include "waflz/limit.h"
#include "waflz/geoip2_mmdb.h"
#include "waflz/enforcer.h"
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
sx_limit::sx_limit(ns_waflz::kv_db &a_db):
        m_limit(NULL),
        m_db(a_db),
        m_enfx(NULL)
{
        m_enfx = new ns_waflz::enforcer(false);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
sx_limit::~sx_limit(void)
{
        if(m_limit) { delete m_limit; m_limit = NULL; }
        if(m_enfx) { delete m_enfx; m_enfx = NULL; }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t sx_limit::init(void)
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
        m_limit = new ns_waflz::limit(m_db);
        l_s = m_limit->load(l_buf, l_buf_len);
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error performing load: Reason: %s\n", m_limit->get_err_msg());
                if(m_limit) { delete m_limit; m_limit = NULL;}
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return STATUS_ERROR;
        }
        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
ns_is2::h_resp_t sx_limit::handle_rqst(waflz_pb::enforcement **ao_enf,
                                       ns_waflz::rqst_ctx **ao_ctx,
                                       ns_is2::session &a_session,
                                       ns_is2::rqst &a_rqst,
                                       const ns_is2::url_pmap_t &a_url_pmap)
{
        if(ao_enf) { *ao_enf = NULL;}
        m_resp = "{\"status\": \"ok\"}";
        if(!m_limit)
        {
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        int32_t l_s;
        ns_waflz::rqst_ctx *l_ctx = NULL;
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
#if 0
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
#endif
        // -------------------------------------------------
        // process enforcers
        // -------------------------------------------------
#if 0
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
#endif
        // -------------------------------------------------
        // process limit
        // -------------------------------------------------
#if 0
        const ::waflz_pb::scope_limit_config& l_slc = a_scope.limits(i_l);
        if(!l_slc.has__reserved_1())
        {
                continue;
        }
        limit *l_limit = (limit *)l_slc._reserved_1();
        bool l_exceeds = false;
        const waflz_pb::condition_group *l_cg = NULL;
        l_limit->process(l_exceeds, &l_cg, a_scope.id(), *ao_rqst_ctx);
        if(!l_exceeds)
        {
                continue;
        }
        if(!l_slc.has_action())
        {
                continue;
        }
        // -------------------------------------------------
        // signal new enforcemnt
        // -------------------------------------------------
        (*ao_rqst_ctx)->m_signal_enf = true;
        // -------------------------------------------------
        // add new exceeds
        // -------------------------------------------------
        const waflz_pb::enforcement& l_axn = l_slc.action();
        int32_t l_s;
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
        // -------------------------------------------------
        // merge enforcement
        // -------------------------------------------------
        //NDBG_OUTPUT("l_enfx: %s\n", l_enfcr->ShortDebugString().c_str());
        l_s = m_enfx->merge(*l_cfg);
        // TODO -return enforcer...
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", m_enfx->get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        if(l_cfg) { delete l_cfg; l_cfg = NULL; }
        // -------------------------------------------------
        // process enforcer
        // -------------------------------------------------
        l_s = m_enfx->process(ao_enf, *ao_rqst_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // enforced???
        // -------------------------------------------------
        if(*ao_enf)
        {
                if((*ao_enf)->has_status())
                {
                        (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
                }
                goto done;
        }
#endif
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
