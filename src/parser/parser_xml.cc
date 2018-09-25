//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    parser_xml.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    04/06/2018
//:
//:   Licensed under the Apache License, Version 2.0 (the "License");
//:   you may not use this file except in compliance with the License.
//:   You may obtain a copy of the License at
//:
//:       http://www.apache.org/licenses/LICENSE-2.0
//:
//:   Unless required by applicable law or agreed to in writing, software
//:   distributed under the License is distributed on an "AS IS" BASIS,
//:   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//:   See the License for the specific language governing permissions and
//:   limitations under the License.
//:
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "parser/parser_xml.h"
#include "support/ndebug.h"
#include "support/trace_internal.h"

//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static xmlParserInputBufferPtr unload_entity(const char *a_uri,
                                             xmlCharEncoding a_enc)
{
        return NULL;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
parser_xml::parser_xml(rqst_ctx *a_rqst_ctx):
        parser(a_rqst_ctx),
        m_doc(),
        m_sax_handler(),
        m_parsing_ctx(),
        m_well_formed(false)
{
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
parser_xml::~parser_xml()
{
        if(m_doc) { xmlFreeDoc(m_doc); m_doc = NULL; }
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t parser_xml::init()
{
        if(m_parsing_ctx)
        {
                xmlFreeParserCtxt(m_parsing_ctx);
                m_parsing_ctx = NULL;
        }
        // -------------------------------------------------
        // unsupported SecXmlExternalEntity action
        // used for schema validation:
        // ----------------------+
        // unsupported operations:
        // ----------------------+
        //   @validateSchema
        //   @validateDtd
        // ----------------------+
        // -------------------------------------------------
        xmlParserInputBufferCreateFilenameFunc l_entity;
        l_entity = xmlParserInputBufferCreateFilenameDefault(unload_entity);
        UNUSED(l_entity);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t parser_xml::process_chunk(const char *a_buf, uint32_t a_len)
{
        // -------------------------------------------------
        // create context if first time...
        // -------------------------------------------------
        if(m_parsing_ctx == NULL)
        {
                m_parsing_ctx = xmlCreatePushParserCtxt(NULL, NULL, a_buf, a_len, "body.xml");
                if(m_parsing_ctx == NULL)
                {
                        // TODO log error??? "XML: Failed to create parsing context."
                        //NDBG_PRINT("xml parse failed...\n");
                        return WAFLZ_STATUS_ERROR;
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // process chunk
        // -------------------------------------------------
        xmlParseChunk(m_parsing_ctx, a_buf, a_len, 0);
        if(m_parsing_ctx->wellFormed == false)
        {
                // TODO log error??? "XML: Failed parsing document."
                //NDBG_PRINT("xml not well formed...\n");
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t parser_xml::finish(void)
{
        if(m_parsing_ctx == NULL)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // signal end of parse
        // -------------------------------------------------
        xmlParseChunk(m_parsing_ctx, NULL, 0, 1);
        // -------------------------------------------------
        // save state
        // -------------------------------------------------
        m_well_formed = m_parsing_ctx->wellFormed;
        m_doc = m_parsing_ctx->myDoc;
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        xmlFreeParserCtxt(m_parsing_ctx);
        m_parsing_ctx = NULL;
        // -------------------------------------------------
        // error on not well formed???
        // -------------------------------------------------
        if(!m_well_formed)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
}
