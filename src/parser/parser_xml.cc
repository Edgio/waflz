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
#include "waflz/rqst_ctx.h"
#include "parser/parser_xml.h"
#include "support/ndebug.h"
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
//: \details print all xml element names (debug)
//: \return  NA
//: \param   xmlNode a_node: xml node object
//: ----------------------------------------------------------------------------
static void print_element_names(xmlNode * a_node)
{
        xmlNode *i_n = NULL;
        for (i_n = a_node; i_n; i_n = i_n->next)
        {
                if (i_n->type == XML_ELEMENT_NODE)
                {
                        NDBG_PRINT("[ELEMENT] name: %s\n", i_n->name);
                }
                else if (i_n->type == XML_ENTITY_DECL)
                {
                        NDBG_PRINT("[%sENTITY %s] name: %s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, i_n->name);
                }
                else
                {
                        NDBG_PRINT("[OTHER  ] name: %s\n", i_n->name);
                }
                print_element_names(i_n->children);
        }
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
        // dump
        // -------------------------------------------------
#if 1
        char *l_buf;
        int l_buf_len;
        NDBG_PRINT("type: %d\n", m_doc->type);
        xmlDocDumpMemory(m_doc, (xmlChar **)&l_buf, &l_buf_len);
        NDBG_PRINT("l_buf: %p\n", l_buf);
        NDBG_PRINT("l_len: %d\n", l_buf_len);
        if(l_buf_len &&
           l_buf)
        {
                NDBG_OUTPUT("%.*s\n", l_buf_len, l_buf);
        }
#endif
        // -------------------------------------------------
        // find entity name value and add
        // -------------------------------------------------
#if 1
        xmlEntityPtr l_xmle;
        l_xmle = ((xmlEntityPtr)(((*(m_doc->children)).children)));
        NDBG_PRINT("xmlE name:     %s\n", (char *)l_xmle->name);
        NDBG_PRINT("xmlE URI:      %s\n", (char *)l_xmle->URI);
        NDBG_PRINT("xmlE SystemID: %s\n", (char *)l_xmle->SystemID);
        arg_t l_arg;
        l_arg.m_key_len = asprintf(&(l_arg.m_key), "%s", l_xmle->name);
        l_arg.m_val_len = asprintf(&(l_arg.m_val), "%s", l_xmle->URI);
        m_rqst_ctx->m_body_arg_list.push_back(l_arg);
#endif
        // -------------------------------------------------
        // print
        // -------------------------------------------------
        //xmlNode *l_root = NULL;
        //l_root = xmlDocGetRootElement(m_doc);
        //print_element_names(l_root);
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
