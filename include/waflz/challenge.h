//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _CHALLENGE_H_
#define _CHALLENGE_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include <map>
#include <vector>
//! ----------------------------------------------------------------------------
//! fwd Decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
        class challenge;
        class problem;
        class event;
}
namespace ns_waflz{
//! ----------------------------------------------------------------------------
//! bot
//! ----------------------------------------------------------------------------
class challenge
{
public:
        //--------------------------------------------------
        // public types
        //--------------------------------------------------
        typedef std::map <int32_t, const waflz_pb::problem*> prob_map_t;
        typedef std::vector <int32_t> prob_vector_t;
        //--------------------------------------------------
        // public methods
        //--------------------------------------------------
        challenge(void);
        ~challenge();
        int32_t load(void* a_js);
        int32_t load(const char* a_buf, uint32_t a_buf_len);
        int32_t load_file(const char* a_file_path, uint32_t a_file_path_len);
        int32_t validate(void);
        int32_t verify(bool& ao_pass, uint32_t a_valid_for_s, rqst_ctx* a_ctx, waflz_pb::event** ao_event);
        int32_t verify_token(bool& ao_pass, const char *a_tk, size_t a_tk_len, data_t &a_ans, uint32_t a_valid_for_s, rqst_ctx* a_ctx, waflz_pb::event **ao_event);
        int32_t get_rand_id(void);
        int32_t get_challenge(const std::string **ao_html, rqst_ctx* a_ctx);
        int32_t get_challenge(const std::string **ao_html, int32_t a_prob_id, rqst_ctx* a_ctx);
        int32_t set_ectoken(int32_t a_ans, rqst_ctx* a_ctx);
        int32_t render_challenge(char** ao_buf, uint32_t &ao_buf_len, rqst_ctx* a_ctx);
        const char* get_err_msg(void)
        {
                return m_err_msg;
        }
private:
        //--------------------------------------------------
        // private methods
        //--------------------------------------------------
        challenge(const challenge &);
        challenge& operator=(const challenge &);
        //--------------------------------------------------
        // private methods
        //--------------------------------------------------
        char m_err_msg[WAFLZ_ERR_LEN];
        waflz_pb::challenge* m_pb;
        prob_map_t m_prob_map;
        prob_vector_t m_prob_vector;
};

}
#endif
