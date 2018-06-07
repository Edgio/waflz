//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    jspb.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    11/30/2016
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
#ifndef __JSPB_H__
#define __JSPB_H__

//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <google/protobuf/message.h>
#include <rapidjson/document.h>

//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#ifndef JSPB_OK
#define JSPB_OK 0
#endif

#ifndef JSPB_ERROR
#define JSPB_ERROR -1
#endif

namespace ns_jspb {

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t convert_to_json(rapidjson::Value &ao_val,
                        rapidjson::Document::AllocatorType &a_alx,
                        const google::protobuf::Message& a_msg);

//: ----------------------------------------------------------------------------
//: \details: Convert a protobuf message to a json object, storing
//:           the result in a rapidjson::Document object.
//: \return:  TODO
//: \param:   msg the protobuf message to convert
//: \param:   value json object to hold the converted value
//: ----------------------------------------------------------------------------
int32_t convert_to_json(rapidjson::Document& ao_js,
                        const google::protobuf::Message& a_msg);

//: ----------------------------------------------------------------------------
//: \details: Convert a protobuf message to json object, storing result in
//:           a std::string.
//: \return:  TODO
//: \param:   msg the protobuf message to convert
//: \param:   value json object to hold the converted value
//: ----------------------------------------------------------------------------
int32_t convert_to_json(std::string& ao_str,
                        const google::protobuf::Message& a_msg);

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t update_from_json(google::protobuf::Message& ao_msg,
                         const rapidjson::Value &a_val);

//: ----------------------------------------------------------------------------
//: \details: Convert a json object to a protobuf message, reading the
//:           json value from a Json::Value object.
//: \return:  TODO
//: \param:   value json object to convert
//: \param:   message protobuf message to hold the converted value
//: ----------------------------------------------------------------------------
int32_t update_from_json(google::protobuf::Message& ao_msg,
                         const rapidjson::Document& a_js);

//: ----------------------------------------------------------------------------
//: \details: Convert a json object to a protobuf message, reading the
//:           json value from a std::string.
//: \return:  TODO
//: \param:   value json object to convert
//: \param:   message protobuf message to hold the converted value
//: ----------------------------------------------------------------------------
int32_t update_from_json(google::protobuf::Message& ao_msg,
                         const char *a_buf,
                         uint32_t a_len);

//: ----------------------------------------------------------------------------
//: \details: Convert a json object to a protobuf message, reading the
//:           json value from a std::string.
//: \return:  TODO
//: \param:   value json object to convert
//: \param:   message protobuf message to hold the converted value
//: ----------------------------------------------------------------------------
int32_t update_from_json(google::protobuf::Message& ao_msg,
                         const std::string& a_str);

//: ----------------------------------------------------------------------------
//: \details: Get last error
//: \return:  Last error reason
//: ----------------------------------------------------------------------------
const char * get_err_msg(void);

//: ----------------------------------------------------------------------------
//: \details: Get last error
//: \return:  Last error reason
//: ----------------------------------------------------------------------------
void set_trace(bool a_val);

} // namespace ns_jspb

#endif // __JSON_PROTOBUF_H__
