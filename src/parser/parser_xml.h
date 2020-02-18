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
#ifndef __PARSER_XML_H
#define __PARSER_XML_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <waflz/parser.h>
#include <libxml/xmlschemas.h>
#include <libxml/xpath.h>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: parser_xml
//: ----------------------------------------------------------------------------
class parser_xml: public parser
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        parser_xml(rqst_ctx *a_rqst_ctx);
        ~parser_xml();
        int32_t init(void);
        int32_t process_chunk(const char *a_buf, uint32_t a_len);
        int32_t finish(void);
        parser_t get_type(void) { return PARSER_XML; }
        void set_capture_xxe(bool a_flag) { m_capture_xxe = a_flag; }
        int32_t capture_xxe(struct _xmlNode *a_xmlNode);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        xmlDocPtr m_doc;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        parser_xml(const parser_xml &);
        parser_xml& operator=(const parser_xml &);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        xmlParserCtxtPtr m_parsing_ctx;
        bool m_well_formed;
        bool m_capture_xxe;
};
}
#endif
