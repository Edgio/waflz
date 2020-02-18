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
void xml_doc_dump(xmlDocPtr a_doc)
{
        char *l_buf;
        int l_buf_len;
        NDBG_PRINT("type: %d\n", a_doc->type);
        xmlDocDumpMemory(a_doc, (xmlChar **)&l_buf, &l_buf_len);
        NDBG_PRINT("l_buf: %p\n", l_buf);
        NDBG_PRINT("l_len: %d\n", l_buf_len);
        if(l_buf_len &&
           l_buf)
        {
                NDBG_OUTPUT("%.*s\n", l_buf_len, l_buf);
        }
}
//: ----------------------------------------------------------------------------
//: \details print all xml element names (debug)
//: \return  NA
//: \param   xmlNode a_node: xml node object
//: ----------------------------------------------------------------------------
void print_element_names(xmlNode * a_node)
{
        xmlNode *i_n = a_node;
        // -------------------------------------------------
        // recurse until no children...
        // -------------------------------------------------
        while(i_n != NULL)
        {
                switch(i_n->type)
                {
                // -----------------------------------------
                // NODE
                // -----------------------------------------
                case XML_ELEMENT_NODE:
                {
                        NDBG_PRINT("[ELEMENT] name: %s\n", i_n->name);
                        break;
                }
                // -----------------------------------------
                // ENTITY
                // -----------------------------------------
                case XML_ENTITY_DECL:
                {
                        NDBG_PRINT("[%sENTITY %s] name: %s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, i_n->name);
                        break;
                }
                // -----------------------------------------
                // OTHER
                // -----------------------------------------
                default:
                {
                        NDBG_PRINT("[OTHER  ] name: %s\n", i_n->name);
                        break;
                }
                }
                // -----------------------------------------
                // recurse if children...
                // -----------------------------------------
                print_element_names(i_n->children);
                // -----------------------------------------
                // iterate
                // -----------------------------------------
                i_n = i_n->next;
        }
}
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
        m_well_formed(false),
        m_capture_xxe(false)
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
        // capture entities?
        // -------------------------------------------------
        if(m_capture_xxe &&
           m_doc &&
           m_doc->children)
        {
                int32_t l_s;
                l_s = capture_xxe(m_doc->children);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO -log error???
                        goto cleanup;
                }
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
cleanup:
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
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t parser_xml::capture_xxe(struct _xmlNode *a_xmlNode)
{
        xmlNode *i_n = a_xmlNode;
        // -------------------------------------------------
        // find XML_DTD_NODE
        // -------------------------------------------------
        while(i_n != NULL)
        {
                switch(i_n->type)
                {
                // -----------------------------------------
                // XML_DTD_NODE
                // -----------------------------------------
                case XML_DTD_NODE:
                {
                        // TODO? only capture xxe in DTD???
                        break;
                }
                // -----------------------------------------
                // XML_ENTITY_DECL
                // -----------------------------------------
                case XML_ENTITY_DECL:
                {
                        xmlEntityPtr l_xmle;
                        l_xmle = (xmlEntityPtr)i_n;
                        if(!l_xmle ||
                           !l_xmle->name)
                        {
                                break;
                        }
                        if(l_xmle->length < 0)
                        {
                                break;
                        }
                        uint32_t l_max_len;
                        l_max_len = rqst_ctx::s_body_arg_len_cap > (uint32_t)l_xmle->length ? (uint32_t)l_xmle->length: rqst_ctx::s_body_arg_len_cap;
                        arg_t l_arg;
                        l_arg.m_key_len = asprintf(&(l_arg.m_key), "%.*s", (int)rqst_ctx::s_body_arg_len_cap, l_xmle->name);
#define _ASSIGN_IF(_item) else if(l_xmle->_item) { \
                l_arg.m_val_len = asprintf(&(l_arg.m_val), "%.*s", (int)l_max_len, l_xmle->_item); }
                        if(0){}
                        _ASSIGN_IF(SystemID)
                        _ASSIGN_IF(URI)
                        _ASSIGN_IF(content)
                        _ASSIGN_IF(orig)
                        else
                        {
                                l_arg.m_val_len = asprintf(&(l_arg.m_val), "%s", "__na__");
                        }
                        m_rqst_ctx->m_body_arg_list.push_back(l_arg);
                        break;
                }
                // -----------------------------------------
                // OTHER
                // -----------------------------------------
                default:
                {
                        break;
                }
                }
                // -----------------------------------------
                // recurse if children...
                // -----------------------------------------
                capture_xxe(i_n->children);
                // -----------------------------------------
                // iterate
                // -----------------------------------------
                i_n = i_n->next;
        }
        return WAFLZ_STATUS_OK;
}
}
