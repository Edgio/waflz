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
#include "waflz/def.h"
#include "waflz/kycb_db.h"
#include "waflz/redis_db.h"
#include "waflz/limit.h"
#include "waflz/geoip2_mmdb.h"
#include "waflz/enforcer.h"
#include "waflz/rqst_ctx.h"
#include "support/file_util.h"
#include "support/time_util.h"
#include "limit.pb.h"
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
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define _GET_HEADER(_header) do { \
        l_d.m_data = _header; \
        l_d.m_len = sizeof(_header); \
        ns_waflz::data_map_t::const_iterator i_h = a_ctx->m_header_map.find(l_d); \
        if(i_h != a_ctx->m_header_map.end()) { \
                l_v.m_data = i_h->second.m_data; \
                l_v.m_len = i_h->second.m_len; \
        } \
        } while(0)
namespace ns_waflz_server {
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
                                  ns_waflz::rqst_ctx *a_ctx)
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
                ns_waflz::data_t l_d;
                ns_waflz::data_t l_v;
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
        m_enf = new waflz_pb::enforcement();
        m_enf->set_enf_type(waflz_pb::enforcement_type_t::enforcement_type_t_BLOCK_REQUEST);
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
        if(m_enf) { delete m_enf; m_enf = NULL; }
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
        const waflz_pb::enforcement *l_enf = NULL;
        // -------------------------------------------------
        // process enforcers
        // -------------------------------------------------
        l_s = m_enfx->process(&l_enf, l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error performing enforcer process.  Reason: %s", m_enfx->get_err_msg());
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        if(l_enf)
        {
                *ao_enf = new waflz_pb::enforcement();
                (*ao_enf)->CopyFrom(*l_enf);
                if(ao_ctx) { *ao_ctx = l_ctx; }
                else if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_DONE;
        }
        // -------------------------------------------------
        // process limit
        // -------------------------------------------------
        bool l_exceeds = false;
        const waflz_pb::condition_group *l_cg = NULL;
        const std::string l_s_id = "__na__";
        l_s = m_limit->process(l_exceeds, &l_cg, l_s_id, l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error performing limit process.  Reason: %s", m_limit->get_err_msg());
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        if(!l_exceeds)
        {
                if(ao_ctx) { *ao_ctx = l_ctx; }
                else if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_DONE;
        }
        // -------------------------------------------------
        // signal new enforcemnt
        // -------------------------------------------------
        l_ctx->m_signal_enf = true;
        // -------------------------------------------------
        // *************************************************
        // add new exceeds
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // create enforcement
        // -------------------------------------------------
        waflz_pb::limit& l_pb = *(m_limit->get_pb());
        waflz_pb::config *l_cfg = new waflz_pb::config();
        l_cfg->set_id(l_pb.id());
        l_cfg->set_name(l_pb.name());
        l_cfg->set_type(waflz_pb::config_type_t_ENFORCER);
        l_cfg->set_customer_id(l_pb.customer_id());
        l_cfg->set_enabled_date(get_date_short_str());
        // -------------------------------------------------
        // populate limit info
        // -------------------------------------------------
        waflz_pb::limit* l_limit = l_cfg->add_limits();
        l_limit->set_id(l_pb.id());
        l_limit->set_customer_id(l_pb.customer_id());
        if(l_pb.has_name())
        {
            l_limit->set_name(l_pb.name());
        }
        else
        {
                l_limit->set_name("__na__");
        }
        l_limit->set_disabled(false);
        // -------------------------------------------------
        // copy conditions
        // -------------------------------------------------
        if(l_cg)
        {
                waflz_pb::condition_group *l_ncg = l_limit->add_condition_groups();
                l_ncg->CopyFrom(*l_cg);
        }
        // -------------------------------------------------
        // create limits for dimensions
        // -------------------------------------------------
        for(int i_k = 0; i_k < l_pb.keys_size(); ++i_k)
        {
                int32_t l_s;
                l_s = add_limit_with_key(*l_limit,
                                         l_pb.keys(i_k),
                                         l_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error performing add_limit_with_key.");
                        if(ao_ctx) { *ao_ctx = l_ctx; }
                        else if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
        }
        // -------------------------------------------------
        // copy action(s)
        // -------------------------------------------------
        uint64_t l_cur_time_ms = ns_waflz::get_time_ms();
        uint32_t l_e_duration_s = 0;
        waflz_pb::enforcement *l_e = l_limit->mutable_action();
        l_e->CopyFrom(*m_enf);
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
                l_e_duration_s = l_pb.duration_sec();
        }
        l_e->set_duration_sec(l_e_duration_s);
        // -------------------------------------------------
        // set duration
        // -------------------------------------------------
        l_limit->set_start_epoch_msec(l_cur_time_ms);
        l_limit->set_end_epoch_msec(l_cur_time_ms + l_e_duration_s*1000);
        //const ::waflz_pb::enforcement& l_a = a_scope.limits(i_l).action();
        // -------------------------------------------------
        // *************************************************
        // merge enforcement
        // *************************************************
        // -------------------------------------------------
        //NDBG_OUTPUT("l_enfx: %s\n", l_enfcr->ShortDebugString().c_str());
        l_s = m_enfx->merge(*l_cfg);
        // TODO -return enforcer...
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error performing merge.");
                if(ao_ctx) { *ao_ctx = l_ctx; }
                else if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        if(l_cfg) { delete l_cfg; l_cfg = NULL; }
        // -------------------------------------------------
        // process enforcer
        // -------------------------------------------------
        l_s = m_enfx->process(&l_enf, l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error performing merge.");
                if(ao_ctx) { *ao_ctx = l_ctx; }
                else if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // create enforcement copy...
        // -------------------------------------------------
done:
        if(l_enf)
        {
                *ao_enf = new waflz_pb::enforcement();
                (*ao_enf)->CopyFrom(*l_enf);
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(ao_ctx) { *ao_ctx = l_ctx; }
        else if(l_ctx) { delete l_ctx; l_ctx = NULL; }
        return ns_is2::H_RESP_DONE;
}
}
