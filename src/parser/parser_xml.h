//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef __PARSER_XML_H
#define __PARSER_XML_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <waflz/parser.h>
#include <libxml/xmlschemas.h>
#include <libxml/xpath.h>
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! parser_xml
//! ----------------------------------------------------------------------------
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
        bool well_formed(void) { return m_well_formed; }
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
