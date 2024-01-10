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
#include "waflz/schema.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>

#include "acl.pb.h"
#include "event.pb.h"
#include "jspb/jspb.h"
#include "op/nms.h"
#include "op/regex.h"
#include "rapidjson/error/en.h"
#include "rapidjson/memorystream.h"
#include "rapidjson/schema.h"
#include "support/ndebug.h"
#include "waflz/acl.h"
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "waflz/string_util.h"
#include "waflz/engine.h"
#include "waflz/trace.h"
#include "support/time_util.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _CONFIG_SCHEMA_MAX_SIZE (1 << 21)
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
/* #define _GET_HEADER(_header, _val)                                 \
    do                                                             \
    {                                                              \
        _val = NULL;                                               \
        _val##_len = 0;                                            \
        l_d.m_data = _header;                                      \
        l_d.m_len = sizeof(_header) - 1;                           \
        data_unordered_map_t::const_iterator i_h = l_hm.find(l_d); \
        if (i_h != l_hm.end())                                     \
        {                                                          \
            _val = i_h->second.m_data;                             \
            _val##_len = i_h->second.m_len;                        \
        }                                                          \
    } while (0) */
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details constructor
//! \return  None
//! \param   None
//! ----------------------------------------------------------------------------
schema::schema(engine& a_engine)
    : m_init(false),
      m_err_msg(),
      m_id(),
      m_api_gw_id(),
      m_cust_id(),
      m_name(),
      m_last_modified_date(),
      m_engine(a_engine),
      m_schema(NULL),
      m_validator(NULL)
{}

//! ----------------------------------------------------------------------------
//! \details import fields from json
//! \return  waflz status code
//! \param   a_doc: rapidjson document representing json config
//! ----------------------------------------------------------------------------
int32_t schema::import_fields(const rapidjson::Document& a_doc) 
{
        // -------------------------------------------------
        // Parse schema
        // set id, api gateway id, customer id and 
        // last_modified_date
        // -------------------------------------------------
        if(!a_doc.HasMember("id") || !a_doc["id"].IsString()) {
                WAFLZ_PERROR(m_err_msg, "missing id");
                return WAFLZ_STATUS_ERROR;
        }
        m_id = a_doc["id"].GetString();

        if(!a_doc.HasMember("api_gw_id") || !a_doc["api_gw_id"].IsString()) {
                WAFLZ_PERROR(m_err_msg, "missing api_gw_id");
                return WAFLZ_STATUS_ERROR;
        }
        m_api_gw_id = a_doc["api_gw_id"].GetString();

        if(!a_doc.HasMember("customer_id") || !a_doc["customer_id"].IsString()) {
                WAFLZ_PERROR(m_err_msg, "missing customer id");
                return WAFLZ_STATUS_ERROR;
        }
        m_cust_id = a_doc["customer_id"].GetString();

        if(!a_doc.HasMember("last_modified_date") || 
           !a_doc["last_modified_date"].IsString()) {
                WAFLZ_PERROR(m_err_msg, "missing last_modified_date");
                return WAFLZ_STATUS_ERROR;
        }
        m_last_modified_date = a_doc["last_modified_date"].GetString();
        if (a_doc.HasMember("name") && a_doc["name"].IsString())
        {
                m_name = a_doc["name"].GetString();
        }
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details Load schema buffer into schema class
//! \return  waflz status code
//! \param   a_buf: Schema Buffer
//! \param   a_buf_len: Schema Buffer Len
//! ----------------------------------------------------------------------------
int32_t schema::load(const char *a_buf, uint32_t a_buf_len)
{
        // -------------------------------------------------
        // Empty schema -> error
        // -------------------------------------------------
        if (!a_buf) { return WAFLZ_STATUS_ERROR; }
        // -------------------------------------------------
        // If schema too big, return error
        // -------------------------------------------------
        if (a_buf_len > _CONFIG_SCHEMA_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg,
                             "config file size(%u) > max size(%u)",
                             a_buf_len,
                             _CONFIG_SCHEMA_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        rapidjson::Document l_doc;
        if (l_doc.Parse(a_buf, a_buf_len).HasParseError())
        {
                WAFLZ_PERROR(m_err_msg, "faled to parse file");
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s = import_fields(l_doc);
        if (l_s == WAFLZ_STATUS_ERROR) { return WAFLZ_STATUS_ERROR; }
        // -------------------------------------------------
        // Delete existing schema
        // -------------------------------------------------
        if (m_schema) { delete m_schema; }
        if (m_validator) { delete m_validator; }
        // -------------------------------------------------
        // Create new validator pointing to schema
        // -------------------------------------------------
        m_schema = new rapidjson::SchemaDocument(l_doc);
        m_validator = new rapidjson::SchemaValidator(*m_schema);
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t schema::load(void* a_js)
{
        const rapidjson::Document &l_doc = *((rapidjson::Document *)a_js);
        int32_t l_s = import_fields(l_doc);
        if (l_s == WAFLZ_STATUS_ERROR) { return WAFLZ_STATUS_ERROR; }
        // -------------------------------------------------
        // Delete existing schema
        // -------------------------------------------------
        if (m_schema) { delete m_schema; }
        if (m_validator) { delete m_validator; }
        // -------------------------------------------------
        // Create new validator pointing to schema
        // -------------------------------------------------
        m_schema = new rapidjson::SchemaDocument(l_doc);
        m_validator = new rapidjson::SchemaValidator(*m_schema);
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Process request against schema
//! \return  waflz status code
//! \param   ao_event: Output event
//! \param   a_ctx: Sailfish context
//! \param   ao_ctx: Output waflz rqst context
//! ----------------------------------------------------------------------------
int32_t schema::process(waflz_pb::event **ao_event,
                        void *a_ctx,
                        ns_waflz::rqst_ctx **ao_ctx)
{
        // -------------------------------------------------
        // Make sure *ao_event can be accessed
        // -------------------------------------------------
        if (!ao_event) { return WAFLZ_STATUS_ERROR; }
        int32_t l_s = (*ao_ctx)->init_phase_1(
            m_engine.get_geoip2_mmdb(), NULL, NULL, NULL);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::init_phase_1");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Init phase 2 for body data
        // -------------------------------------------------
        l_s = (*ao_ctx)->init_phase_2(m_engine.get_ctype_parser_map());
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::init_phase_2");
                return WAFLZ_STATUS_ERROR;
        }
        *ao_event = NULL;
        // -------------------------------------------------
        // Create data stream to be read
        // -------------------------------------------------
        size_t l_parse_len = (*ao_ctx)->m_body_len;
        /*
        if ((*ao_ctx)->m_body_data_truncated)
        {
                for (int32_t l_ind = (*ao_ctx)->m_body_len - 1;
                     l_parse_len != 0 &&
                     (std::isdigit((*ao_ctx)->m_body_data[l_ind]) ||
                      std::isalpha((*ao_ctx)->m_body_data[l_ind]) ||
                      (*ao_ctx)->m_body_data[l_ind] == '.' ||
                      (*ao_ctx)->m_body_data[l_ind] == '\\');
                     --l_ind)
                {
                        l_parse_len--;
                }
        }
        */
        // -------------------------------------------------
        // Create data stream to be parsed
        // -------------------------------------------------
        rapidjson::MemoryStream l_body_data_stream((*ao_ctx)->m_body_data,
                                                   l_parse_len);
        rapidjson::Reader l_reader;
        // -------------------------------------------------
        // Parse and validate data (*m_validator has schema)
        // -------------------------------------------------
        bool l_parse_result = l_reader.Parse(l_body_data_stream, *m_validator);
        // -------------------------------------------------
        // If an error occured in parsing...
        // -------------------------------------------------
        if (!l_parse_result)
        {
                // -----------------------------------------
                // Validation Error
                // -----------------------------------------
                if (!m_validator->IsValid())
                {
                        waflz_pb::event *l_event = new ::waflz_pb::event();
                        l_event->set_schema_config_id(m_id);
                        l_event->set_schema_config_name(m_name);
                        l_event->set_rule_msg("JSON Schema Validation Error");
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        // l_sevent->set_rule_id(TODO);
                        //  --------------------------------
                        //  Schema Violation
                        //  --------------------------------
                        std::string err =
                            m_validator->GetInvalidSchemaKeyword();
                        l_sevent->set_rule_msg(err);
                        l_sevent->set_schema_error_offset(
                            std::to_string(l_reader.GetErrorOffset()));
                        *ao_event = l_event;
                }
                // -----------------------------------------
                // Parsing Error
                // -----------------------------------------
                else if (l_reader.HasParseError())
                {
                        waflz_pb::event *l_event = new ::waflz_pb::event();
                        l_event->set_rule_msg("JSON Schema Parsing Error");
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        // l_sevent->set_rule_id(TODO);
                        //  --------------------------------
                        //  JSON Parse Error
                        //  --------------------------------
                        std::string err = rapidjson::GetParseError_En(
                            l_reader.GetParseErrorCode());
                        l_sevent->set_rule_msg(err);
                        l_sevent->set_schema_error_offset(
                            std::to_string(l_reader.GetErrorOffset()));
                        *ao_event = l_event;
                }
        }
        m_validator->Reset();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Set Schema Document and create validator pointing to it
//! \return  None
//! \param   a_schema_doc: Schema Document to set
//! ----------------------------------------------------------------------------
void schema::set_schema_document(rapidjson::SchemaDocument *a_schema_doc)
{
        if (!a_schema_doc) return;
        if (m_schema) { delete m_schema; }
        m_schema = a_schema_doc;
        // -------------------------------------------------
        // Create validator pointing to schema
        // -------------------------------------------------
        if (m_validator) { delete m_validator; }
        m_validator = new rapidjson::SchemaValidator(*m_schema);
}
//! ----------------------------------------------------------------------------
//! \brief   dtor
//! \deatils
//! \return  None
//! ----------------------------------------------------------------------------
schema::~schema(void)
{
        if (m_validator)
        {
                delete m_validator;
                m_validator = NULL;
        }
        if (m_schema)
        {
                delete m_schema;
                m_schema = NULL;
        }
}
}  // namespace ns_waflz
