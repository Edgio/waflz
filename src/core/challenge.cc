//! ----------------------------------------------------------------------------
//! Copyright (C) 2018 Verizon.  All Rights Reserved.
//! All Rights Reserved
///
//!  @file    challenge.cc
//!  @brief
//!  @author  Revathi Sabanayagam
//!  @date    01/06/2018
///
//!   Licensed under the Apache License, Version 2.0 (the "License");
//!   you may not use this file except in compliance with the License.
//!   You may obtain a copy of the License at
///
//!       http://www.apache.org/licenses/LICENSE-2.0
///
//!   Unless required by applicable law or agreed to in writing, software
//!   distributed under the License is distributed on an "AS IS" BASIS,
//!   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//!   See the License for the specific language governing permissions and
//!   limitations under the License.
///
//! ----------------------------------------------------------------------------
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "waflz/challenge.h"
#include "waflz/render.h"
#include "waflz/string_util.h"
#include "jspb/jspb.h"
#include "scope.pb.h"
#include "event.pb.h"
#include "rapidjson/document.h"
#include "rapidjson/error/error.h"
#include "rapidjson/error/en.h"
#include "ectoken/ectoken_v3.h"
#include "support/file_util.h"
#include "support/ndebug.h"
#include "support/time_util.h"
#include "support/base64.h"
#include "core/decode.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
// default ectoken key...
#define _DEFAULT_KEY "b9RCuEKmbYTd4DDP"
// the maximum size of the json defining configuration for bot (1MB)
#define CONFIG_SECURITY_CHALLENGE_CONFIG_MAX_SIZE (1<<20)
// ectoken payload params...
#define _TOKEN_FIELD_IP "ip"
#define _TOKEN_FIELD_UA "ua"
#define _TOKEN_FIELD_TIME "time"
#define _TOKEN_FIELD_ANS "ans"
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
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
namespace ns_waflz
{
///-----------------------------------------------------------------------------
//! @brief  constructor
//! ----------------------------------------------------------------------------
challenge::challenge(void):
                    m_err_msg(),
                    m_pb(NULL),
                    m_prob_map(),
                    m_prob_vector()
{
}
//! ----------------------------------------------------------------------------
//! @brief  destructor
//! ----------------------------------------------------------------------------
challenge::~challenge()
{
        if(m_pb) { delete m_pb; m_pb = NULL;}
}
//! ----------------------------------------------------------------------------
//! @brief  validates the challenge  for mandatory fields
//! @return WAFLZ_STATUS_OK on success, WAFLZ_STATUS_ERROR on failure
//! ----------------------------------------------------------------------------
int32_t challenge::validate()
{
        if(!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(m_pb->problems_size() <= 0)
        {
                WAFLZ_PERROR(m_err_msg, "config should have atleast one problem");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate each problem...
        // -------------------------------------------------
        for(int i_c = 0 ; i_c < m_pb->problems_size(); ++i_c)
        {
                waflz_pb::problem& i_p = *(m_pb->mutable_problems(i_c));
                if(!i_p.has_id())
                {
                        WAFLZ_PERROR(m_err_msg, "problem missing id");
                        return WAFLZ_STATUS_ERROR;
                }
                if(!i_p.has_response_body_base64() ||
                    i_p.response_body_base64().empty())
                {
                        WAFLZ_PERROR(m_err_msg, "problem missing response_body_base64");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @brief  Loads the bot challenge json and validates it
//! @param  <a_js> - browser challenges in json format
//! @return WAFLZ_STATUS_OK on success, WAFLZ_STATUS_ERROR on failure
//! ----------------------------------------------------------------------------
int32_t challenge::load(void* a_js)
{
        if(!a_js)
        {
                WAFLZ_PERROR(m_err_msg, "a_js == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // parse load/json...
        // -------------------------------------------------
        m_pb = new waflz_pb::challenge();
        const rapidjson::Value &l_js = *((rapidjson::Value *)a_js);
        int32_t l_s;
        l_s = update_from_json(*m_pb, l_js);
        if(l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json: Reason: %s", get_jspb_err_msg());
                if(m_pb) { delete m_pb; m_pb = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate...
        // -------------------------------------------------
        l_s = validate();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // seed random...
        // -------------------------------------------------
        srand(get_time_ms());
        // -------------------------------------------------
        // load in...
        // -------------------------------------------------
        m_prob_map.clear();
        m_prob_vector.clear();
        for(int i_c = 0 ; i_c < m_pb->problems_size(); ++i_c)
        {
                const waflz_pb::problem& i_p = m_pb->problems(i_c);
                int32_t l_id = i_p.id();
                m_prob_map[l_id] = &i_p;
                m_prob_vector.push_back(l_id);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @brief  load bot challenge from buufer containing json
//! @param  <a_buf> - input buffer containing bot config
//! @param  <a_buf_len> - length of the buffer
//! @return  WAFLZ_STATUS_OK on success, WAFLZ_STATUS_ERROR on failure
//! ----------------------------------------------------------------------------
int32_t challenge::load(const char* a_buf, uint32_t a_buf_len)
{
        // -------------------------------------------------
        // check buffer length
        // -------------------------------------------------
        if(a_buf_len > CONFIG_SECURITY_CHALLENGE_CONFIG_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                             a_buf_len,
                             CONFIG_SECURITY_CHALLENGE_CONFIG_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        rapidjson::Document *l_js = new rapidjson::Document();
        rapidjson::ParseResult l_ok;
        l_ok = l_js->Parse(a_buf, a_buf_len);
        if(!l_ok)
        {
                WAFLZ_PERROR(m_err_msg, "JSON parse error: %s (%d)",
                             rapidjson::GetParseError_En(l_ok.Code()), (int)l_ok.Offset());
                if(l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_js->IsObject())
        {
                WAFLZ_PERROR(m_err_msg, "error parsing json");
                if(l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check type
        // -------------------------------------------------
        if(!l_js->IsObject())
        {
                WAFLZ_PERROR(m_err_msg, "error parsing json");
                if(l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // load
        // -------------------------------------------------
        int32_t l_s;
        l_s = load((void *)l_js);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_js) { delete l_js; l_js = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        if(l_js) { delete l_js; l_js = NULL;}
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @brief   loads the bot challenges from json
//!          add it to corresponding maps
//! @param   <a_file_path> - path to file
//! @param   <a_file_path_len> - length of a_file_path
//! @return  WAFLZ_STATUS_OK on success, WAFLZ_STATUS_ERROR on failure
//! ----------------------------------------------------------------------------
int32_t challenge::load_file(const char* a_file_path, uint32_t a_file_path_len)
{
        int32_t l_s;
        char *l_buf = NULL;
        uint32_t l_buf_len;
        l_s = read_file(a_file_path, &l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing read_file: %s",
                             a_file_path);
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return WAFLZ_STATUS_ERROR;
        }
        l_s = load(l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return WAFLZ_STATUS_ERROR;
        }
        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @brief   get random problem id for browser challenge
//! @param   <ao_problem_id> - output var to store the id
//! @return  WAFLZ_STATUS_OK on success, WAFLZ_STATUS_ERROR on failure
//! ----------------------------------------------------------------------------
int32_t challenge::get_rand_id(void)
{
        int32_t l_size = m_prob_vector.size();
        if(l_size <= 0)
        {
                WAFLZ_PERROR(m_err_msg, "%s", "problem vector is empty");
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_index = rand() % l_size;
        // return @ index 0 for others...
        if((l_index < 0 ) || 
            (l_index >= l_size))
        {
                l_index = 0;
        }
        return m_prob_vector[l_index];
}
//! ----------------------------------------------------------------------------
//! @brief   get a decoded browser challenge with ectoken
//! @param   <ao_problem_id> - output var to store the id
//! @return  WAFLZ_STATUS_OK on success, WAFLZ_STATUS_ERROR on failure
//! ----------------------------------------------------------------------------
int32_t challenge::get_challenge(const std::string** ao_html, rqst_ctx* a_ctx)
{
        int32_t l_id = get_rand_id();
        if(l_id == WAFLZ_STATUS_ERROR)
        {
                WAFLZ_PERROR(m_err_msg, "getting random problem id failed");
                return WAFLZ_STATUS_ERROR;
        }
        return get_challenge(ao_html, l_id, a_ctx);
}
//! ----------------------------------------------------------------------------
//! @brief   get a decoded browser challenge with ectoken
//! @param   <ao_problem_id> - output var to store the id
//! @return  WAFLZ_STATUS_OK on success, WAFLZ_STATUS_ERROR on failure
//! ----------------------------------------------------------------------------
int32_t challenge::get_challenge(const std::string **ao_html, int32_t a_prob_id, rqst_ctx* a_ctx)
{
        int32_t l_s;
        if(!a_ctx)
        {
                WAFLZ_PERROR(m_err_msg, "rqst_ctx == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(!ao_html)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_html = NULL;
        // -------------------------------------------------
        // get challenge string using prob_id
        // -------------------------------------------------
        prob_map_t::const_iterator i_c = m_prob_map.begin();
        i_c = m_prob_map.find(a_prob_id);
        if(i_c == m_prob_map.end())
        {
                WAFLZ_PERROR(m_err_msg, "%s", "problem id not found in the config");
                return WAFLZ_STATUS_ERROR;
        }
        const waflz_pb::problem &l_p = *(i_c->second);
        *ao_html = &(l_p.response_body_base64());
        if(a_ctx->s_get_bot_ch_prob)
        {
                l_s = a_ctx->s_get_bot_ch_prob(a_ctx->m_bot_ch, &a_ctx->m_ans);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "failed to get bot challenge");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // get ectoken
        // -------------------------------------------------
        l_s = set_ectoken(a_ctx->m_ans, a_ctx);
        if(l_s != 0)
        {
                WAFLZ_PERROR(m_err_msg, "set_ectoken failed");
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @brief   get ectoken. ectoken formed with ip, ua from ctx, random problem
//!          id and current time in epoch seconds
//! @param   <ao_ectoken> - output variable for ectoken
//! @param   <ao_prob_id> - prob id used in the ectoken
//! @return  WAFLZ_STATUS_OK on success, WAFLZ_STATUS_ERROR on failure
//! ----------------------------------------------------------------------------
int32_t challenge::set_ectoken(int32_t a_ans,
                               rqst_ctx* a_ctx)
{
        int32_t l_s;
        if(!a_ctx)
        {
                WAFLZ_PERROR(m_err_msg, "rqst_ctx == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get user-agent
        // -------------------------------------------------
        data_t l_d;
        data_t l_v;
        _GET_HEADER("User-Agent");
        // -------------------------------------------------
        // get current time in microseconds
        // -------------------------------------------------
        uint64_t l_ct = get_time_s();
        // -------------------------------------------------
        // format ectoken input
        // -------------------------------------------------
        char *l_token_clr = NULL;
        int l_token_clr_len = 0;
        l_token_clr_len = asprintf(&l_token_clr,
                                   "ip=%.*s&ua=%.*s&time=%" PRIu64 "&ans=%d",
                                   a_ctx->m_src_addr.m_len,
                                   a_ctx->m_src_addr.m_data,
                                   l_v.m_len,
                                   l_v.m_data,
                                   l_ct,
                                   a_ans);
        if(l_token_clr_len < 0)
        {
                if(l_token_clr) { free(l_token_clr); l_token_clr = NULL; }
                WAFLZ_PERROR(m_err_msg, "sprintf failed");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // encrypt ectoken
        // -------------------------------------------------
        size_t l_token_len = 0;
        l_token_len = ns_ectoken_v3::ectoken_encrypt_required_size(l_token_clr_len);
        char *l_token = NULL;
        l_token = (char *)malloc(l_token_len);
        l_s = ns_ectoken_v3::ectoken_encrypt_token(l_token,
                                                   &l_token_len,
                                                   l_token_clr,
                                                   l_token_clr_len,
                                                   _DEFAULT_KEY,
                                                   sizeof(_DEFAULT_KEY) - 1);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "ectoken encrypt failed");
                if(l_token_clr) { free(l_token_clr); l_token_clr = NULL; }
                if(l_token) { free(l_token); l_token = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // add to rqst_ctx
        // -------------------------------------------------
        a_ctx->m_token.m_data = l_token;
        a_ctx->m_token.m_len = l_token_len;
        //NDBG_PRINT("TOKEN: %.*s\n", (int)l_token_len, l_token);
        if(l_token_clr) { free(l_token_clr); l_token_clr = NULL; }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @brief   TODO
//! @param   TODO
//! @return  WAFLZ_STATUS_OK on success, WAFLZ_STATUS_ERROR on failure
//! ----------------------------------------------------------------------------
int32_t challenge::render_challenge(char** ao_buf, uint32_t &ao_buf_len, rqst_ctx* a_ctx)
{
        const std::string *l_b64 = NULL;
        int32_t l_s;
        l_s = get_challenge(&l_b64, a_ctx);
        if((l_s != WAFLZ_STATUS_OK) ||
            !l_b64)
        {
                return WAFLZ_STATUS_ERROR;
        }
        if(l_b64->empty())
        {
               return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // decode
        // -------------------------------------------------
        char *l_dcd = NULL;
        size_t l_dcd_len = 0;
        l_s = b64_decode(&l_dcd, l_dcd_len, l_b64->c_str(), l_b64->length());
        if(l_s != WAFLZ_STATUS_OK)
        {
                // error???

                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // render
        // -------------------------------------------------
        char *l_rndr = NULL;
        size_t l_rndr_len = 0;
        l_s = render(&l_rndr, l_rndr_len, l_dcd, l_dcd_len, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // error???
                if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                if(l_rndr) { free(l_rndr); l_rndr = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // set/cleanup
        // -------------------------------------------------
        if(l_dcd) { free(l_dcd); l_dcd = NULL; }
        *ao_buf = l_rndr;
        ao_buf_len = l_rndr_len;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @brief TODO
//! @param <ao_arg_list> - arg list to clean
//! @return TODO
//! ----------------------------------------------------------------------------
static void free_arg_list(arg_list_t &ao_arg_list)
{
        for(arg_list_t::iterator i_q = ao_arg_list.begin();
            i_q != ao_arg_list.end();
            ++i_q)
        {
                if(i_q->m_key) { free(i_q->m_key); i_q->m_key = NULL; }
                if(i_q->m_val) { free(i_q->m_val); i_q->m_val = NULL; }
        }
}
//! ----------------------------------------------------------------------------
//! @brief TODO
//! @param <ao_pass> - true if challenge passed -false otherwise
//! @param <a_ctx>   - request ctx
//! @return TODO
//! ----------------------------------------------------------------------------
int32_t challenge::verify_token(bool& ao_pass,
                                const char *a_tk,
                                size_t a_tk_len,
                                data_t &a_ans,
                                uint32_t a_valid_for_s,
                                rqst_ctx* a_ctx,
                                waflz_pb::event **ao_event)
{
        int32_t l_s;
        // -------------------------------------------------
        // parse args in the token
        // -------------------------------------------------
        arg_list_t l_tk_list;
        data_map_t l_tk_map;
        uint32_t l_unused;
        l_s = parse_args(l_tk_list, l_unused, a_tk, a_tk_len, '&');
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "ec token decrypt failed");
                (*ao_event)->set_challenge_status(waflz_pb::event_chal_status_t_CHAL_STATUS_TOKEN_CORRUPTED);
                free_arg_list(l_tk_list);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // add to map
        // -------------------------------------------------
        for(arg_list_t::const_iterator i_a = l_tk_list.begin();
            i_a != l_tk_list.end();
            ++i_a)
        {
                data_t l_key;
                l_key.m_data = i_a->m_key;
                l_key.m_len = i_a->m_key_len;
                data_t l_val;
                l_val.m_data = i_a->m_val;
                l_val.m_len = i_a->m_val_len;
                l_tk_map[l_key] = l_val;
        }
        // -------------------------------------------------
        // macro...
        // -------------------------------------------------
        data_map_t::const_iterator i_t;
        data_t l_key;
#define _GET_TOKEN_FIELD_FIELD(_field) do { \
        l_key.m_data = _field; \
        l_key.m_len = sizeof(_field) - 1; \
        i_t = l_tk_map.find(l_key); \
        if(i_t == l_tk_map.end()) { \
                WAFLZ_PERROR(m_err_msg, "missing %s in token", _field); \
                return WAFLZ_STATUS_ERROR; \
        } } while(0)
        // -------------------------------------------------
        // validate ip
        // -------------------------------------------------
        _GET_TOKEN_FIELD_FIELD(_TOKEN_FIELD_IP);
        if((a_ctx->m_src_addr.m_data == NULL) ||
           (a_ctx->m_src_addr.m_len <= 0))
        {
                WAFLZ_PERROR(m_err_msg, "ip missing in the ctx");
                (*ao_event)->set_challenge_status(waflz_pb::event_chal_status_t_CHAL_STATUS_IP_MISMATCH);
                free_arg_list(l_tk_list);
                return WAFLZ_STATUS_ERROR;
        }
        if(strncmp(a_ctx->m_src_addr.m_data, i_t->second.m_data, i_t->second.m_len) != 0)
        {
                WAFLZ_PERROR(m_err_msg, "token ip validation failed");
                (*ao_event)->set_challenge_status(waflz_pb::event_chal_status_t_CHAL_STATUS_IP_MISMATCH);
                free_arg_list(l_tk_list);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get user-agent
        // -------------------------------------------------
        data_t l_d;
        data_t l_v;
        _GET_HEADER("User-Agent");
        // -------------------------------------------------
        // validate ua
        // -------------------------------------------------
        _GET_TOKEN_FIELD_FIELD(_TOKEN_FIELD_UA);
        if((l_v.m_data == NULL) ||
           (l_v.m_len <= 0))
        {
                WAFLZ_PERROR(m_err_msg, "user-agent missing in the ctx");
                (*ao_event)->set_challenge_status(waflz_pb::event_chal_status_t_CHAL_STATUS_UA_MISMATCH);
                free_arg_list(l_tk_list);
                return WAFLZ_STATUS_ERROR;
        }
        if(strncmp(l_v.m_data, i_t->second.m_data, i_t->second.m_len) != 0)
        {
                WAFLZ_PERROR(m_err_msg, "token user-agent validation failed");
                (*ao_event)->set_challenge_status(waflz_pb::event_chal_status_t_CHAL_STATUS_UA_MISMATCH);
                free_arg_list(l_tk_list);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate time
        // -------------------------------------------------
        _GET_TOKEN_FIELD_FIELD(_TOKEN_FIELD_TIME);
        uint64_t l_time_cur = get_time_s();
        uint64_t l_time_tok = (uint64_t)strntol(i_t->second.m_data, i_t->second.m_len, NULL, 10);
        if((l_time_cur-l_time_tok) >= a_valid_for_s)
        {
                WAFLZ_PERROR(m_err_msg, "token expired");
                (*ao_event)->set_challenge_status(waflz_pb::event_chal_status_t_CHAL_STATUS_TOKEN_EXPIRED);
                free_arg_list(l_tk_list);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate problem/answer
        // -------------------------------------------------
        _GET_TOKEN_FIELD_FIELD(_TOKEN_FIELD_ANS);
        // -------------------------------------------------
        // check solution...
        // -------------------------------------------------
        if(strncmp(i_t->second.m_data, a_ans.m_data, a_ans.m_len) != 0)
        {
                WAFLZ_PERROR(m_err_msg, "challenge verification failed");
                (*ao_event)->set_challenge_status(waflz_pb::event_chal_status_t_CHAL_STATUS_WRONG_ANSWER);
                free_arg_list(l_tk_list);
                return WAFLZ_STATUS_ERROR;
        }
        // challenge passed...
        ao_pass = true;
        free_arg_list(l_tk_list);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @brief check if the request has bc cookie and verify the result.
//! @param <ao_pass> - true if challenge passed -false otherwise
//! @param <a_ctx>   - request ctx
//! @return WAFLZ_STATUS_OK if bc verification passed or to be issued,
//!         WAFLZ_STATUS_ERROR if bc verification failed
//! ----------------------------------------------------------------------------
int32_t challenge::verify(bool& ao_pass, uint32_t a_valid_for_s, rqst_ctx* a_ctx, waflz_pb::event **ao_event)
{
        ao_pass = false;
        data_t l_ck_k;
        data_map_t::const_iterator i_h;
        // -------------------------------------------------
        // get ec_secure
        // -------------------------------------------------
        l_ck_k.m_data = "ec_secure";
        l_ck_k.m_len = sizeof("ec_secure") - 1;
        i_h = a_ctx->m_cookie_map.find(l_ck_k);
        if(i_h == a_ctx->m_cookie_map.end())
        {
                (*ao_event)->set_challenge_status(waflz_pb::event_chal_status_t_CHAL_STATUS_NO_TOKEN);
                return WAFLZ_STATUS_OK;
        }
        data_t l_ck_secure;
        l_ck_secure = i_h->second;
        // -------------------------------------------------
        // get ec_answer
        // -------------------------------------------------
        l_ck_k.m_data = "ec_answer";
        l_ck_k.m_len = sizeof("ec_answer") - 1;
        i_h = a_ctx->m_cookie_map.find(l_ck_k);
        if(i_h == a_ctx->m_cookie_map.end())
        {
                (*ao_event)->set_challenge_status(waflz_pb::event_chal_status_t_CHAL_STATUS_NO_TOKEN);
                return WAFLZ_STATUS_OK;
        }
        data_t l_ck_answer;
        l_ck_answer = i_h->second;
        // -------------------------------------------------
        // decrypt ectoken
        // -------------------------------------------------
        size_t l_tk_len = ns_ectoken_v3::ectoken_decrypt_required_size(l_ck_secure.m_len);
        char *l_tk = NULL;
        l_tk = (char *)malloc(l_tk_len);
        int l_s;
        l_s = ns_ectoken_v3::ectoken_decrypt_token(l_tk,
                                                   &l_tk_len,
                                                   l_ck_secure.m_data,
                                                   l_ck_secure.m_len,
                                                   _DEFAULT_KEY,
                                                   sizeof(_DEFAULT_KEY) - 1);
        if(l_s != 0)
        {
                WAFLZ_PERROR(m_err_msg, "ec token decrypt failed");
                (*ao_event)->set_challenge_status(waflz_pb::event_chal_status_t_CHAL_STATUS_TOKEN_CORRUPTED);
                if(l_tk) { free(l_tk); l_tk = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // verify
        // -------------------------------------------------
        l_s = verify_token(ao_pass, l_tk, l_tk_len, l_ck_answer, a_valid_for_s, a_ctx, ao_event);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_tk) { free(l_tk); l_tk = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        if(l_tk) { free(l_tk); l_tk = NULL; }
        return WAFLZ_STATUS_OK;
}
}
