//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_ac.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    12/06/2016
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
//: Includes
//: ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "parser/parser_xml.h"
#include "support/ndebug.h"
#include <string.h>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define XML_SHORT "<monkeys><gorilla>coco</gorilla><mandrill>dooby</mandrill><baboon>groovy</baboon></monkeys>"
#define XML_W_XXE "<?xml version=\"1.0\" encoding=\"UTF-8\"?> <!DOCTYPE foo [ <!ENTITY writer \"Donald Duck.\"> <!ENTITY copyright \"Copyright W3Schools.\"> <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]> <body>   <type>default</type>   <way>my_cool_method</way>   <person>     <name>joeblow</name>     <email>who@what.com</email>     <!-- <hash>abc1234</hash> -->   </person>   <thing>BONKERS</thing>   <thang>EATATJOES</thang>   <reference>BANANAS</reference> </body>"
//: ----------------------------------------------------------------------------
//: json parse
//: ----------------------------------------------------------------------------
TEST_CASE( "xml parse basic test", "[xml_parse_basic]" ) {
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("xml parse basic") {
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 8096, true);
                ns_waflz::parser_xml *l_p_xml = new ns_waflz::parser_xml(l_rqst_ctx);
                l_rqst_ctx->m_body_parser = l_p_xml;
                int32_t l_s;
                l_s = l_p_xml->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_xml->process_chunk(XML_SHORT, strlen(XML_SHORT));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_xml->finish();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                xmlDocPtr l_doc = l_p_xml->m_doc;
                // -----------------------------------------
                // basic document validation
                // -----------------------------------------
                REQUIRE((l_p_xml->well_formed() == true));
                REQUIRE((l_doc != NULL));
                REQUIRE((l_doc->type == XML_DOCUMENT_NODE));
                REQUIRE((l_doc->children != NULL));
                REQUIRE((l_doc->children->type == XML_ELEMENT_NODE));
                REQUIRE((l_doc->children->name != NULL));
                REQUIRE((strcmp((const char*)l_doc->children->name,"monkeys")==0));
                REQUIRE((l_rqst_ctx->m_body_arg_list.size() == 0));
                // -----------------------------------------
                // display...
                // -----------------------------------------
                //NDBG_PRINT("l_doc->type: %d\n", l_doc->type);
                //NDBG_PRINT("l_doc->children->type: %d\n", l_doc->children->type);
                //NDBG_PRINT("l_doc->children->name: %s\n", l_doc->children->name);
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("xml parse no xxe") {
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 8096, true);
                ns_waflz::parser_xml *l_p_xml = new ns_waflz::parser_xml(l_rqst_ctx);
                l_rqst_ctx->m_body_parser = l_p_xml;
                int32_t l_s;
                l_s = l_p_xml->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_xml->process_chunk(XML_W_XXE, strlen(XML_W_XXE));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_xml->finish();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                xmlDocPtr l_doc = l_p_xml->m_doc;
                // -----------------------------------------
                // display...
                // -----------------------------------------
                //NDBG_PRINT("l_doc->type: %d\n", l_doc->type);
                //NDBG_PRINT("l_doc->children->type: %d\n", l_doc->children->type);
                //NDBG_PRINT("l_doc->children->name: %s\n", l_doc->children->name);
                // -----------------------------------------
                // basic document validation
                // -----------------------------------------
                REQUIRE((l_p_xml->well_formed() == true));
                REQUIRE((l_doc != NULL));
                REQUIRE((l_doc->type == XML_DOCUMENT_NODE));
                REQUIRE((l_doc->children != NULL));
                REQUIRE((l_doc->children->type == XML_DTD_NODE));
                REQUIRE((l_doc->children->name != NULL));
                REQUIRE((strcmp((const char*)l_doc->children->name,"foo")==0));
                REQUIRE((l_rqst_ctx->m_body_arg_list.size() == 0));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("xml parse xxe") {
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 8096, true);
                ns_waflz::parser_xml *l_p_xml = new ns_waflz::parser_xml(l_rqst_ctx);
                l_rqst_ctx->m_body_parser = l_p_xml;
                l_p_xml->set_capture_xxe(true);
                int32_t l_s;
                l_s = l_p_xml->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_xml->process_chunk(XML_W_XXE, strlen(XML_W_XXE));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_xml->finish();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                xmlDocPtr l_doc = l_p_xml->m_doc;
                // -----------------------------------------
                // display...
                // -----------------------------------------
                //NDBG_PRINT("l_doc->type: %d\n", l_doc->type);
                //NDBG_PRINT("l_doc->children->type: %d\n", l_doc->children->type);
                //NDBG_PRINT("l_doc->children->name: %s\n", l_doc->children->name);
                // -----------------------------------------
                // basic document validation
                // -----------------------------------------
                REQUIRE((l_p_xml->well_formed() == true));
                REQUIRE((l_doc != NULL));
                REQUIRE((l_doc->type == XML_DOCUMENT_NODE));
                REQUIRE((l_doc->children != NULL));
                REQUIRE((l_rqst_ctx->m_body_arg_list.size() == 3));
                uint32_t i_arg = 0;
                for(ns_waflz::arg_list_t::const_iterator i_q = l_rqst_ctx->m_body_arg_list.begin();
                    i_q != l_rqst_ctx->m_body_arg_list.end();
                    ++i_q, ++i_arg)
                {
                        //NDBG_PRINT(": [%d]%.*s: [%d]%.*s\n",
                        //           i_q->m_key_len, i_q->m_key_len, i_q->m_key,
                        //           i_q->m_val_len, i_q->m_val_len, i_q->m_val);
                        switch(i_arg)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_q->m_key, "writer", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "Donald Duck.", i_q->m_val_len) == 0));
                                break;
                        }
                        case 1:
                        {
                                REQUIRE((strncmp(i_q->m_key, "copyright", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "Copyright W3Schools.", i_q->m_val_len) == 0));
                                break;
                        }
                        case 2:
                        {
                                REQUIRE((strncmp(i_q->m_key, "xxe", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "file:///etc/passwd", i_q->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
}
