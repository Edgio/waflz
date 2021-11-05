//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef __JSPB_H__
#define __JSPB_H__
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <google/protobuf/message.h>
#include <rapidjson/document.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef JSPB_OK
#define JSPB_OK 0
#endif
#ifndef JSPB_ERROR
#define JSPB_ERROR -1
#endif
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t convert_to_json(rapidjson::Value &ao_val,
                        rapidjson::Document::AllocatorType &a_alx,
                        const google::protobuf::Message& a_msg);
//! ----------------------------------------------------------------------------
//! \details: Convert a protobuf message to a json object, storing
//!           the result in a rapidjson::Document object.
//! \return:  TODO
//! \param:   msg the protobuf message to convert
//! \param:   value json object to hold the converted value
//! ----------------------------------------------------------------------------
int32_t convert_to_json(rapidjson::Document& ao_js,
                        const google::protobuf::Message& a_msg);
//! ----------------------------------------------------------------------------
//! \details: Convert a protobuf message to json object, storing result in
//!           a std::string.
//! \return:  TODO
//! \param:   msg the protobuf message to convert
//! \param:   value json object to hold the converted value
//! ----------------------------------------------------------------------------
int32_t convert_to_json(std::string& ao_str,
                        const google::protobuf::Message& a_msg);
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t update_from_json(google::protobuf::Message& ao_msg,
                         const rapidjson::Value &a_val);
//! ----------------------------------------------------------------------------
//! \details: Convert a json object to a protobuf message, reading the
//!           json value from a Json::Value object.
//! \return:  TODO
//! \param:   value json object to convert
//! \param:   message protobuf message to hold the converted value
//! ----------------------------------------------------------------------------
int32_t update_from_json(google::protobuf::Message& ao_msg,
                         const rapidjson::Document& a_js);
//! ----------------------------------------------------------------------------
//! \details: Convert a json object to a protobuf message, reading the
//!           json value from a std::string.
//! \return:  TODO
//! \param:   value json object to convert
//! \param:   message protobuf message to hold the converted value
//! ----------------------------------------------------------------------------
int32_t update_from_json(google::protobuf::Message& ao_msg,
                         const char *a_buf,
                         uint32_t a_len);
//! ----------------------------------------------------------------------------
//! \details: Convert a json object to a protobuf message, reading the
//!           json value from a std::string.
//! \return:  TODO
//! \param:   value json object to convert
//! \param:   message protobuf message to hold the converted value
//! ----------------------------------------------------------------------------
int32_t update_from_json(google::protobuf::Message& ao_msg,
                         const std::string& a_str);
//! ----------------------------------------------------------------------------
//! \details: Get last error
//! \return:  Last error reason
//! ----------------------------------------------------------------------------
const char * get_jspb_err_msg(void);
//! ----------------------------------------------------------------------------
//! \details: Get last error
//! \return:  Last error reason
//! ----------------------------------------------------------------------------
void set_trace(bool a_val);
} // namespace ns_waflz
#endif // __JSON_PROTOBUF_H__
