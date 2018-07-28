//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_instances.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    03/28/2017
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
#include "waflz/engine.h"
#include "waflz/def.h"
#include "waflz/instances.h"
#include "waflz/instance.h"
#include "waflz/profile.h"
#include "waflz/rqst_ctx.h"
#include "jspb/jspb.h"
#include "event.pb.h"
#include "config.pb.h"
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
//: ----------------------------------------------------------------------------
//: Config
//: ----------------------------------------------------------------------------
#define WAF_CONF_1001_JSON "{\"id\":\"1001\",\"name\":\"Default Policy for www.edgecast.com\",\"customer_id\":\"0050\",\"enabled_date\":\"03/13/2014\",\"audit_profile_action\":\"alert\",\"audit_profile\":{\"name\":\"my_cool_audit_profile_name\",\"id\":\"my_cool_audit_profile_id\",\"ruleset_id\":\"OWASP-CRS-2.2.9\",\"ruleset_version\":\"2017-08-01\",\"access_settings\":{\"ip\":{\"whitelist\":[],\"blacklist\":[]},\"country\":{\"whitelist\":[],\"blacklist\":[]},\"url\":{\"whitelist\":[],\"blacklist\":[]},\"referer\":{\"whitelist\":[],\"blacklist\":[]}},\"general_settings\":{\"engine\":\"anomaly\",\"debug_log\":\"/tmp/modsec-debug-audit.log\",\"debug_level\":1,\"allowed_http_methods\":[\"GET\"],\"allowed_http_versions\":[\"HTTP/1.1\"],\"allowed_request_content_types\":[\"application/x-www-form-urlencoded\",\"multipart/form-data\",\"text/xml\",\"application/xml\",\"application/x-amf\",\"application/json\"],\"disallowed_extensions\":[\".asa\",\".asax\",\".ascx\",\".axd\",\".backup\",\".bak\",\".bat\",\".cdx\",\".cer\",\".cfg\",\".cmd\",\".com\",\".config\",\".conf\",\".cs\",\".csproj\",\".csr\",\".dat\",\".db\",\".dbf\",\".dll\",\".dos\",\".htr\",\".htw\",\".ida\",\".idc\",\".idq\",\".inc\",\".ini\",\".key\",\".licx\",\".lnk\",\".log\",\".mdb\",\".old\",\".pass\",\".pdb\",\".pol\",\".printer\",\".pwd\",\".resources\",\".resx\",\".sql\",\".sys\",\".vb\",\".vbs\",\".vbproj\",\".vsdisco\",\".webinfo\",\".xsd\",\".xsx/\"],\"disallowed_headers\":[\"Proxy-Connection\",\"Lock-Token\",\"Content-Range\",\"Translate\",\"if\"],\"max_num_args\":4,\"arg_name_length\":100,\"arg_length\":400,\"total_arg_length\":64000,\"max_file_size\":1048576,\"combined_file_sizes\":1048576,\"validate_utf8_encoding\":true,\"xml_parser\":true,\"process_request_body\":true,\"process_response_body\":false,\"response_header_name\":\"X-1001-EC-Security-Audit\",\"response_mime_types\":[\"text/plain\",\"text/html\",\"text/xml\"],\"anomaly_settings\":{\"critical_score\":5,\"error_score\":4,\"warning_score\":3,\"notice_score\":2,\"inbound_threshold\":5,\"outbound_threshold\":4}},\"disabled_policies\":[],\"disabled_rules\":[],\"custom_rules\":[]},\"prod_profile_action\":\"block\",\"prod_profile\":{\"name\":\"my_cool_production_profile_name\",\"id\":\"my_cool_production_profile_id\",\"ruleset_id\":\"OWASP-CRS-2.2.9\",\"ruleset_version\":\"2017-08-01\",\"access_settings\":{\"ip\":{\"whitelist\":[\"192.168.1.1\",\"192.168.2.1\",\"127.0.0.1\",\"192.168.3.0/24\",\"2606:2888:4033:197:2cb0:e933:d3:2f9f\",\"2606:2888:4033:197:2cb0:e933:d3:4000/126\"],\"blacklist\":[\"8.8.8.0/24\",\"4.2.2.2\",\"2606:2888:4033:197:2cb0:e933:d3:2f9e\",\"2606:2888:4033:197:2cb0:e933:d3:3000/126\"]},\"country\":{\"whitelist\":[\"US\",\"CA\"],\"blacklist\":[\"RU\",\"CN\"]},\"url\":{\"whitelist\":[\"robots.txt\"],\"blacklist\":[\"password\",\"httpd.conf\"]},\"referer\":{\"whitelist\":[\"www.google.com\"],\"blacklist\":[\".*.imgur.com\",\"www.malware.com\"]},\"user-agent\":{\"whitelist\":[\"hlo\"],\"blacklist\":[\"curl\",\"^$\"]},\"cookie\":{\"whitelist\":[\"awesome\"],\"blacklist\":[\"awww\"]},\"ignore_header\":[\"benign-header\",\"super-whatever-header\"],\"ignore_cookie\":[\"sketchy_origin\",\"yousocrazy\"]},\"general_settings\":{\"engine\":\"anomaly\",\"debug_log\":\"/tmp/modsec-debug-1001.log\",\"debug_level\":1,\"allowed_http_methods\":[\"GET\"],\"allowed_http_versions\":[\"HTTP/1.1\"],\"allowed_request_content_types\":[\"application/x-www-form-urlencoded\",\"multipart/form-data\",\"text/xml\",\"application/xml\",\"application/x-amf\",\"application/json\"],\"disallowed_extensions\":[\".asa\",\".asax\",\".ascx\",\".axd\",\".backup\",\".bak\",\".bat\",\".cdx\",\".cer\",\".cfg\",\".cmd\",\".com\",\".config\",\".conf\",\".cs\",\".csproj\",\".csr\",\".dat\",\".db\",\".dbf\",\".dll\",\".dos\",\".htr\",\".htw\",\".ida\",\".idc\",\".idq\",\".inc\",\".ini\",\".key\",\".licx\",\".lnk\",\".log\",\".mdb\",\".old\",\".pass\",\".pdb\",\".pol\",\".printer\",\".pwd\",\".resources\",\".resx\",\".sql\",\".sys\",\".vb\",\".vbs\",\".vbproj\",\".vsdisco\",\".webinfo\",\".xsd\",\".xsx/\"],\"disallowed_headers\":[\"Proxy-Connection\",\"Lock-Token\",\"Content-Range\",\"Translate\",\"if\"],\"max_num_args\":3,\"arg_name_length\":100,\"arg_length\":400,\"total_arg_length\":64000,\"max_file_size\":1048576,\"combined_file_sizes\":1048576,\"validate_utf8_encoding\":true,\"xml_parser\":true,\"process_request_body\":true,\"process_response_body\":false,\"response_header_name\":\"X-1001-EC-Security\",\"response_mime_types\":[\"text/plain\",\"text/html\",\"text/xml\"],\"anomaly_settings\":{\"critical_score\":5,\"error_score\":4,\"warning_score\":3,\"notice_score\":2,\"inbound_threshold\":1,\"outbound_threshold\":4}},\"disabled_policies\":[{\"policy_id\":\"modsecurity_crs_20_protocol_violations.conf\"}],\"disabled_rules\":[{\"rule_id\":\"981320\"}],\"custom_rules\":[{\"rule_id\":\"100\",\"description\":\"this will need to be fleshed out seriously in the future, but the basic idea is that this can hold an abstract representation of a rule, that gets rendered into modsec language as its loaded.\"}]}}"
#define WAF_CONF_1001_W_LM_DATE_JSON "{\"id\":\"1001\",\"name\":\"Default Policy for www.edgecast.com\",\"customer_id\":\"0050\",\"last_modified_date\":\"2016-07-20T00:45:20.744583Z\",\"enabled_date\":\"03/13/2014\",\"audit_profile_action\":\"alert\",\"audit_profile\":{\"name\":\"my_cool_audit_profile_name\",\"id\":\"my_cool_audit_profile_id\",\"ruleset_id\":\"OWASP-CRS-2.2.9\",\"ruleset_version\":\"2017-08-01\",\"access_settings\":{\"ip\":{\"whitelist\":[],\"blacklist\":[]},\"country\":{\"whitelist\":[],\"blacklist\":[]},\"url\":{\"whitelist\":[],\"blacklist\":[]},\"referer\":{\"whitelist\":[],\"blacklist\":[]}},\"general_settings\":{\"engine\":\"anomaly\",\"debug_log\":\"/tmp/modsec-debug-audit.log\",\"debug_level\":1,\"allowed_http_methods\":[\"GET\"],\"allowed_http_versions\":[\"HTTP/1.1\"],\"allowed_request_content_types\":[\"application/x-www-form-urlencoded\",\"multipart/form-data\",\"text/xml\",\"application/xml\",\"application/x-amf\",\"application/json\"],\"disallowed_extensions\":[\".asa\",\".asax\",\".ascx\",\".axd\",\".backup\",\".bak\",\".bat\",\".cdx\",\".cer\",\".cfg\",\".cmd\",\".com\",\".config\",\".conf\",\".cs\",\".csproj\",\".csr\",\".dat\",\".db\",\".dbf\",\".dll\",\".dos\",\".htr\",\".htw\",\".ida\",\".idc\",\".idq\",\".inc\",\".ini\",\".key\",\".licx\",\".lnk\",\".log\",\".mdb\",\".old\",\".pass\",\".pdb\",\".pol\",\".printer\",\".pwd\",\".resources\",\".resx\",\".sql\",\".sys\",\".vb\",\".vbs\",\".vbproj\",\".vsdisco\",\".webinfo\",\".xsd\",\".xsx/\"],\"disallowed_headers\":[\"Proxy-Connection\",\"Lock-Token\",\"Content-Range\",\"Translate\",\"if\"],\"max_num_args\":4,\"arg_name_length\":100,\"arg_length\":400,\"total_arg_length\":64000,\"max_file_size\":1048576,\"combined_file_sizes\":1048576,\"validate_utf8_encoding\":true,\"xml_parser\":true,\"process_request_body\":true,\"process_response_body\":false,\"response_header_name\":\"X-1001-EC-Security-Audit\",\"response_mime_types\":[\"text/plain\",\"text/html\",\"text/xml\"],\"anomaly_settings\":{\"critical_score\":5,\"error_score\":4,\"warning_score\":3,\"notice_score\":2,\"inbound_threshold\":5,\"outbound_threshold\":4}},\"disabled_policies\":[],\"disabled_rules\":[],\"custom_rules\":[]},\"prod_profile_action\":\"block\",\"prod_profile\":{\"name\":\"my_cool_production_profile_name\",\"id\":\"my_cool_production_profile_id\",\"ruleset_id\":\"OWASP-CRS-2.2.9\",\"ruleset_version\":\"2017-08-01\",\"access_settings\":{\"ip\":{\"whitelist\":[\"192.168.1.1\",\"192.168.2.1\",\"127.0.0.1\",\"192.168.3.0/24\",\"2606:2888:4033:197:2cb0:e933:d3:2f9f\",\"2606:2888:4033:197:2cb0:e933:d3:4000/126\"],\"blacklist\":[\"8.8.8.0/24\",\"4.2.2.2\",\"2606:2888:4033:197:2cb0:e933:d3:2f9e\",\"2606:2888:4033:197:2cb0:e933:d3:3000/126\"]},\"country\":{\"whitelist\":[\"US\",\"CA\"],\"blacklist\":[\"RU\",\"CN\"]},\"url\":{\"whitelist\":[\"robots.txt\"],\"blacklist\":[\"password\",\"httpd.conf\"]},\"referer\":{\"whitelist\":[\"www.google.com\"],\"blacklist\":[\".*.imgur.com\",\"www.malware.com\"]},\"user-agent\":{\"whitelist\":[\"hlo\"],\"blacklist\":[\"curl\",\"^$\"]},\"cookie\":{\"whitelist\":[\"awesome\"],\"blacklist\":[\"awww\"]},\"ignore_header\":[\"benign-header\",\"super-whatever-header\"],\"ignore_cookie\":[\"sketchy_origin\",\"yousocrazy\"]},\"general_settings\":{\"engine\":\"anomaly\",\"debug_log\":\"/tmp/modsec-debug-1001.log\",\"debug_level\":1,\"allowed_http_methods\":[\"GET\"],\"allowed_http_versions\":[\"HTTP/1.1\"],\"allowed_request_content_types\":[\"application/x-www-form-urlencoded\",\"multipart/form-data\",\"text/xml\",\"application/xml\",\"application/x-amf\",\"application/json\"],\"disallowed_extensions\":[\".asa\",\".asax\",\".ascx\",\".axd\",\".backup\",\".bak\",\".bat\",\".cdx\",\".cer\",\".cfg\",\".cmd\",\".com\",\".config\",\".conf\",\".cs\",\".csproj\",\".csr\",\".dat\",\".db\",\".dbf\",\".dll\",\".dos\",\".htr\",\".htw\",\".ida\",\".idc\",\".idq\",\".inc\",\".ini\",\".key\",\".licx\",\".lnk\",\".log\",\".mdb\",\".old\",\".pass\",\".pdb\",\".pol\",\".printer\",\".pwd\",\".resources\",\".resx\",\".sql\",\".sys\",\".vb\",\".vbs\",\".vbproj\",\".vsdisco\",\".webinfo\",\".xsd\",\".xsx/\"],\"disallowed_headers\":[\"Proxy-Connection\",\"Lock-Token\",\"Content-Range\",\"Translate\",\"if\"],\"max_num_args\":3,\"arg_name_length\":100,\"arg_length\":400,\"total_arg_length\":64000,\"max_file_size\":1048576,\"combined_file_sizes\":1048576,\"validate_utf8_encoding\":true,\"xml_parser\":true,\"process_request_body\":true,\"process_response_body\":false,\"response_header_name\":\"X-1001-EC-Security\",\"response_mime_types\":[\"text/plain\",\"text/html\",\"text/xml\"],\"anomaly_settings\":{\"critical_score\":5,\"error_score\":4,\"warning_score\":3,\"notice_score\":2,\"inbound_threshold\":1,\"outbound_threshold\":4}},\"disabled_policies\":[{\"policy_id\":\"modsecurity_crs_20_protocol_violations.conf\"}],\"disabled_rules\":[{\"rule_id\":\"981320\"}],\"custom_rules\":[{\"rule_id\":\"100\",\"description\":\"this will need to be fleshed out seriously in the future, but the basic idea is that this can hold an abstract representation of a rule, that gets rendered into modsec language as its loaded.\"}]}}"
#define WAF_CONF_1001_W_NEW_LM_DATE_JSON "{\"id\":\"1001\",\"name\":\"Default Policy for www.edgecast.com\",\"customer_id\":\"0050\",\"last_modified_date\":\"2016-08-25T00:45:20.744583Z\",\"enabled_date\":\"03/13/2014\",\"audit_profile_action\":\"alert\",\"audit_profile\":{\"name\":\"my_cool_audit_profile_name\",\"id\":\"my_cool_audit_profile_id\",\"ruleset_id\":\"OWASP-CRS-2.2.9\",\"ruleset_version\":\"2017-08-01\",\"access_settings\":{\"ip\":{\"whitelist\":[],\"blacklist\":[]},\"country\":{\"whitelist\":[],\"blacklist\":[]},\"url\":{\"whitelist\":[],\"blacklist\":[]},\"referer\":{\"whitelist\":[],\"blacklist\":[]}},\"general_settings\":{\"engine\":\"anomaly\",\"debug_log\":\"/tmp/modsec-debug-audit.log\",\"debug_level\":1,\"allowed_http_methods\":[\"GET\"],\"allowed_http_versions\":[\"HTTP/1.1\"],\"allowed_request_content_types\":[\"application/x-www-form-urlencoded\",\"multipart/form-data\",\"text/xml\",\"application/xml\",\"application/x-amf\",\"application/json\"],\"disallowed_extensions\":[\".asa\",\".asax\",\".ascx\",\".axd\",\".backup\",\".bak\",\".bat\",\".cdx\",\".cer\",\".cfg\",\".cmd\",\".com\",\".config\",\".conf\",\".cs\",\".csproj\",\".csr\",\".dat\",\".db\",\".dbf\",\".dll\",\".dos\",\".htr\",\".htw\",\".ida\",\".idc\",\".idq\",\".inc\",\".ini\",\".key\",\".licx\",\".lnk\",\".log\",\".mdb\",\".old\",\".pass\",\".pdb\",\".pol\",\".printer\",\".pwd\",\".resources\",\".resx\",\".sql\",\".sys\",\".vb\",\".vbs\",\".vbproj\",\".vsdisco\",\".webinfo\",\".xsd\",\".xsx/\"],\"disallowed_headers\":[\"Proxy-Connection\",\"Lock-Token\",\"Content-Range\",\"Translate\",\"if\"],\"max_num_args\":4,\"arg_name_length\":100,\"arg_length\":400,\"total_arg_length\":64000,\"max_file_size\":1048576,\"combined_file_sizes\":1048576,\"validate_utf8_encoding\":true,\"xml_parser\":true,\"process_request_body\":true,\"process_response_body\":false,\"response_header_name\":\"X-1001-EC-Security-Audit\",\"response_mime_types\":[\"text/plain\",\"text/html\",\"text/xml\"],\"anomaly_settings\":{\"critical_score\":5,\"error_score\":4,\"warning_score\":3,\"notice_score\":2,\"inbound_threshold\":5,\"outbound_threshold\":4}},\"disabled_policies\":[],\"disabled_rules\":[],\"custom_rules\":[]},\"prod_profile_action\":\"block\",\"prod_profile\":{\"name\":\"my_cool_production_profile_name\",\"id\":\"my_cool_production_profile_id\",\"ruleset_id\":\"OWASP-CRS-2.2.9\",\"ruleset_version\":\"2017-08-01\",\"access_settings\":{\"ip\":{\"whitelist\":[\"192.168.1.1\",\"192.168.2.1\",\"127.0.0.1\",\"192.168.3.0/24\",\"2606:2888:4033:197:2cb0:e933:d3:2f9f\",\"2606:2888:4033:197:2cb0:e933:d3:4000/126\"],\"blacklist\":[\"8.8.8.0/24\",\"4.2.2.2\",\"2606:2888:4033:197:2cb0:e933:d3:2f9e\",\"2606:2888:4033:197:2cb0:e933:d3:3000/126\"]},\"country\":{\"whitelist\":[\"US\",\"CA\"],\"blacklist\":[\"RU\",\"CN\"]},\"url\":{\"whitelist\":[\"robots.txt\"],\"blacklist\":[\"password\",\"httpd.conf\"]},\"referer\":{\"whitelist\":[\"www.google.com\"],\"blacklist\":[\".*.imgur.com\",\"www.malware.com\"]},\"user-agent\":{\"whitelist\":[\"hlo\"],\"blacklist\":[\"curl\",\"^$\"]},\"cookie\":{\"whitelist\":[\"awesome\"],\"blacklist\":[\"awww\"]},\"ignore_header\":[\"benign-header\",\"super-whatever-header\"],\"ignore_cookie\":[\"sketchy_origin\",\"yousocrazy\"]},\"general_settings\":{\"engine\":\"anomaly\",\"debug_log\":\"/tmp/modsec-debug-1001.log\",\"debug_level\":1,\"allowed_http_methods\":[\"GET\"],\"allowed_http_versions\":[\"HTTP/1.1\"],\"allowed_request_content_types\":[\"application/x-www-form-urlencoded\",\"multipart/form-data\",\"text/xml\",\"application/xml\",\"application/x-amf\",\"application/json\"],\"disallowed_extensions\":[\".asa\",\".asax\",\".ascx\",\".axd\",\".backup\",\".bak\",\".bat\",\".cdx\",\".cer\",\".cfg\",\".cmd\",\".com\",\".config\",\".conf\",\".cs\",\".csproj\",\".csr\",\".dat\",\".db\",\".dbf\",\".dll\",\".dos\",\".htr\",\".htw\",\".ida\",\".idc\",\".idq\",\".inc\",\".ini\",\".key\",\".licx\",\".lnk\",\".log\",\".mdb\",\".old\",\".pass\",\".pdb\",\".pol\",\".printer\",\".pwd\",\".resources\",\".resx\",\".sql\",\".sys\",\".vb\",\".vbs\",\".vbproj\",\".vsdisco\",\".webinfo\",\".xsd\",\".xsx/\"],\"disallowed_headers\":[\"Proxy-Connection\",\"Lock-Token\",\"Content-Range\",\"Translate\",\"if\"],\"max_num_args\":3,\"arg_name_length\":100,\"arg_length\":400,\"total_arg_length\":64000,\"max_file_size\":1048576,\"combined_file_sizes\":1048576,\"validate_utf8_encoding\":true,\"xml_parser\":true,\"process_request_body\":true,\"process_response_body\":false,\"response_header_name\":\"X-1001-EC-Security\",\"response_mime_types\":[\"text/plain\",\"text/html\",\"text/xml\"],\"anomaly_settings\":{\"critical_score\":5,\"error_score\":4,\"warning_score\":3,\"notice_score\":2,\"inbound_threshold\":1,\"outbound_threshold\":4}},\"disabled_policies\":[{\"policy_id\":\"modsecurity_crs_20_protocol_violations.conf\"}],\"disabled_rules\":[{\"rule_id\":\"981320\"}],\"custom_rules\":[{\"rule_id\":\"100\",\"description\":\"this will need to be fleshed out seriously in the future, but the basic idea is that this can hold an abstract representation of a rule, that gets rendered into modsec language as its loaded.\"}]}}"
#define WAF_CONF_1002_JSON "{\"id\":\"1002\",\"name\":\"Default Policy for www.edgecast.com\",\"customer_id\":\"0050\",\"enabled_date\":\"03/13/2014\",\"audit_profile_action\":\"alert\",\"audit_profile\":{\"name\":\"my_cool_audit_profile_name\",\"id\":\"my_cool_audit_profile_id\",\"ruleset_id\":\"OWASP-CRS-2.2.9\",\"ruleset_version\":\"2017-08-88\",\"access_settings\":{\"ip\":{\"whitelist\":[],\"blacklist\":[]},\"country\":{\"whitelist\":[],\"blacklist\":[]},\"url\":{\"whitelist\":[],\"blacklist\":[]},\"referer\":{\"whitelist\":[],\"blacklist\":[]}},\"general_settings\":{\"engine\":\"anomaly\",\"debug_log\":\"/tmp/modsec-debug-audit.log\",\"debug_level\":1,\"allowed_http_methods\":[\"GET\"],\"allowed_http_versions\":[\"HTTP/1.1\"],\"allowed_request_content_types\":[\"application/x-www-form-urlencoded\",\"multipart/form-data\",\"text/xml\",\"application/xml\",\"application/x-amf\",\"application/json\"],\"disallowed_extensions\":[\".asa\",\".asax\",\".ascx\",\".axd\",\".backup\",\".bak\",\".bat\",\".cdx\",\".cer\",\".cfg\",\".cmd\",\".com\",\".config\",\".conf\",\".cs\",\".csproj\",\".csr\",\".dat\",\".db\",\".dbf\",\".dll\",\".dos\",\".htr\",\".htw\",\".ida\",\".idc\",\".idq\",\".inc\",\".ini\",\".key\",\".licx\",\".lnk\",\".log\",\".mdb\",\".old\",\".pass\",\".pdb\",\".pol\",\".printer\",\".pwd\",\".resources\",\".resx\",\".sql\",\".sys\",\".vb\",\".vbs\",\".vbproj\",\".vsdisco\",\".webinfo\",\".xsd\",\".xsx/\"],\"disallowed_headers\":[\"Proxy-Connection\",\"Lock-Token\",\"Content-Range\",\"Translate\",\"if\"],\"max_num_args\":4,\"arg_name_length\":100,\"arg_length\":400,\"total_arg_length\":64000,\"max_file_size\":1048576,\"combined_file_sizes\":1048576,\"validate_utf8_encoding\":true,\"xml_parser\":true,\"process_request_body\":true,\"process_response_body\":false,\"response_header_name\":\"X-1001-EC-Security-Audit\",\"response_mime_types\":[\"text/plain\",\"text/html\",\"text/xml\"],\"anomaly_settings\":{\"critical_score\":5,\"error_score\":4,\"warning_score\":3,\"notice_score\":2,\"inbound_threshold\":5,\"outbound_threshold\":4}},\"disabled_policies\":[],\"disabled_rules\":[],\"custom_rules\":[]},\"prod_profile_action\":\"block\",\"prod_profile\":{\"name\":\"my_cool_production_profile_name\",\"id\":\"my_cool_production_profile_id\",\"ruleset_id\":\"OWASP-CRS-2.2.9\",\"ruleset_version\":\"2017-08-01\",\"access_settings\":{\"ip\":{\"whitelist\":[\"192.168.1.1\",\"192.168.2.1\",\"127.0.0.1\",\"192.168.3.0/24\",\"2606:2888:4033:197:2cb0:e933:d3:2f9f\",\"2606:2888:4033:197:2cb0:e933:d3:4000/126\"],\"blacklist\":[\"8.8.8.0/24\",\"4.2.2.2\",\"2606:2888:4033:197:2cb0:e933:d3:2f9e\",\"2606:2888:4033:197:2cb0:e933:d3:3000/126\"]},\"country\":{\"whitelist\":[\"US\",\"CA\"],\"blacklist\":[\"RU\",\"CN\"]},\"url\":{\"whitelist\":[\"robots.txt\"],\"blacklist\":[\"password\",\"httpd.conf\"]},\"referer\":{\"whitelist\":[\"www.google.com\"],\"blacklist\":[\".*.imgur.com\",\"www.malware.com\"]},\"user-agent\":{\"whitelist\":[\"hlo\"],\"blacklist\":[\"curl\",\"^$\"]},\"cookie\":{\"whitelist\":[\"awesome\"],\"blacklist\":[\"awww\"]},\"ignore_header\":[\"benign-header\",\"super-whatever-header\"],\"ignore_cookie\":[\"sketchy_origin\",\"yousocrazy\"]},\"general_settings\":{\"engine\":\"anomaly\",\"debug_log\":\"/tmp/modsec-debug-1001.log\",\"debug_level\":1,\"allowed_http_methods\":[\"GET\"],\"allowed_http_versions\":[\"HTTP/1.1\"],\"allowed_request_content_types\":[\"application/x-www-form-urlencoded\",\"multipart/form-data\",\"text/xml\",\"application/xml\",\"application/x-amf\",\"application/json\"],\"disallowed_extensions\":[\".asa\",\".asax\",\".ascx\",\".axd\",\".backup\",\".bak\",\".bat\",\".cdx\",\".cer\",\".cfg\",\".cmd\",\".com\",\".config\",\".conf\",\".cs\",\".csproj\",\".csr\",\".dat\",\".db\",\".dbf\",\".dll\",\".dos\",\".htr\",\".htw\",\".ida\",\".idc\",\".idq\",\".inc\",\".ini\",\".key\",\".licx\",\".lnk\",\".log\",\".mdb\",\".old\",\".pass\",\".pdb\",\".pol\",\".printer\",\".pwd\",\".resources\",\".resx\",\".sql\",\".sys\",\".vb\",\".vbs\",\".vbproj\",\".vsdisco\",\".webinfo\",\".xsd\",\".xsx/\"],\"disallowed_headers\":[\"Proxy-Connection\",\"Lock-Token\",\"Content-Range\",\"Translate\",\"if\"],\"max_num_args\":3,\"arg_name_length\":100,\"arg_length\":400,\"total_arg_length\":64000,\"max_file_size\":1048576,\"combined_file_sizes\":1048576,\"validate_utf8_encoding\":true,\"xml_parser\":true,\"process_request_body\":true,\"process_response_body\":false,\"response_header_name\":\"X-1001-EC-Security\",\"response_mime_types\":[\"text/plain\",\"text/html\",\"text/xml\"],\"anomaly_settings\":{\"critical_score\":5,\"error_score\":4,\"warning_score\":3,\"notice_score\":2,\"inbound_threshold\":1,\"outbound_threshold\":4}},\"disabled_policies\":[{\"policy_id\":\"modsecurity_crs_20_protocol_violations.conf\"}],\"disabled_rules\":[{\"rule_id\":\"981320\"}],\"custom_rules\":[{\"rule_id\":\"100\",\"description\":\"this will need to be fleshed out seriously in the future, but the basic idea is that this can hold an abstract representation of a rule, that gets rendered into modsec language as its loaded.\"}]}}"
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_src_addr_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_uri[] = "243.49.2.0";
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_line_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "GET /800050/origin.testsuite.com/sec_arg_check/info.html?a=%27select%20*%20from%20test_5%27 HTTP/1.1";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_method_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "GET";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_protocol_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "HTTP/1.1";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_scheme_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "http";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_port_cb(uint32_t &a_val, void *a_ctx)
{
        a_val = 80;
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_uri_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "/800050/origin.testsuite.com/sec_arg_check/info.html?a=%27select%20*%20from%20test_5%27";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_query_str_long_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "mooooooooooooooooooooooooooooooooooooooooooooooooooooonnnnnnnnnnnnnnnnkkkkkkkkkkkkkkkkkkeeeeeeeeeeeeeeeyyyyyyyyyyssssss=100000000000000000000000000000000000000";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_query_str_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "a=%27select%20*%20from%20test_5%27";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t &a_val, void *a_ctx)
{
        a_val = 3;
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_header_w_idx_cb(const char **ao_key,
                                        uint32_t &ao_key_len,
                                        const char **ao_val,
                                        uint32_t &ao_val_len,
                                        void *a_ctx,
                                        uint32_t a_idx)
{
        switch(a_idx)
        {
        case 0:
        {
                static const char s_host_key[] = "Host";
                *ao_key = s_host_key;
                ao_key_len = strlen(s_host_key);
                static const char s_host_val[] = "www.google.com";
                *ao_val = s_host_val;
                ao_val_len = strlen(s_host_val);
                break;
        }
        case 1:
        {
                static const char s_ua_key[] = "User-Agent";
                *ao_key = s_ua_key;
                ao_key_len = strlen(s_ua_key);
                static const char s_ua_val[] = "curl/7.47.0";
                *ao_val = s_ua_val;
                ao_val_len = strlen(s_ua_val);
                break;
        }
        case 2:
        {
                static const char s_acct_key[] = "Accept";
                *ao_key = s_acct_key;
                ao_key_len = strlen(s_acct_key);
                static const char s_acct_val[] = "*/*";
                *ao_val = s_acct_val;
                ao_val_len = strlen(s_acct_val);
                break;
        }
        default:
        {
                static const char s_host_key_d[] = "Host";
                *ao_key = s_host_key_d;
                ao_key_len = strlen(s_host_key_d);
                static const char s_host_value_d[] = "www.google.com";
                *ao_val = s_host_value_d;
                ao_val_len = strlen(s_host_value_d);
                break;
        }
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: instances tests
//: ----------------------------------------------------------------------------
TEST_CASE( "instances test", "[instances]" ) {

        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        SECTION("Verify load") {
                // -----------------------------------------
                // touch geoip db file
                // -----------------------------------------
                int l_fd = open("/tmp/BOGUS_GEO_DATABASE.db", O_RDWR | O_CREAT | O_TRUNC,
                                                              S_IRUSR | S_IWUSR |
                                                              S_IRGRP | S_IWGRP |
                                                              S_IROTH | S_IWOTH);
                if(l_fd == -1)
                {
                        printf("error performing open. reason: %s\n", strerror(errno));
                }
                REQUIRE((l_fd != -1));
                // -----------------------------------------
                // get ruleset dir
                // -----------------------------------------
                char l_cwd[1024];
                if (getcwd(l_cwd, sizeof(l_cwd)) != NULL)
                {
                    //fprintf(stdout, "Current working dir: %s\n", l_cwd);
                }
                std::string l_rule_dir = l_cwd;
                l_rule_dir += "/../../../../tests/data/waf/ruleset/";
                //l_rule_dir += "/../tests/data/waf/ruleset/";
                //set_trace(true);
                // -----------------------------------------
                // callbacks
                // -----------------------------------------
                ns_waflz::profile::s_ruleset_dir = l_rule_dir;
                std::string l_geoip2_city_file = l_cwd;
                std::string l_geoip2_asn_file = l_cwd;
                l_geoip2_city_file += "/../../../../tests/data/waf/db/GeoLite2-City.mmdb";
                //l_geoip2_city_file += "/../tests/data/waf/db/GeoLite2-City.mmdb";
                l_geoip2_asn_file += "/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb";
                //l_geoip2_asn_file += "/../tests/data/waf/db/GeoLite2-ASN.mmdb";
                ns_waflz::profile::s_geoip2_db = l_geoip2_city_file;
                ns_waflz::profile::s_geoip2_isp_db = l_geoip2_asn_file;
                // waf
                ns_waflz::rqst_ctx::s_get_rqst_src_addr_cb = get_rqst_src_addr_cb;
                ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_cb;
                ns_waflz::rqst_ctx::s_get_rqst_query_str_cb = get_rqst_query_str_cb;
                ns_waflz::rqst_ctx::s_get_rqst_line_cb = get_rqst_line_cb;
                ns_waflz::rqst_ctx::s_get_rqst_scheme_cb = get_rqst_scheme_cb;
                ns_waflz::rqst_ctx::s_get_rqst_port_cb = get_rqst_port_cb;
                ns_waflz::rqst_ctx::s_get_rqst_method_cb = get_rqst_method_cb;
                ns_waflz::rqst_ctx::s_get_rqst_protocol_cb = get_rqst_protocol_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_cb;
                //ns_waflz::rqst_ctx::s_get_rqst_id_cb = get_rqst_id_cb;
                // -----------------------------------------
                // init
                // -----------------------------------------
                ns_waflz::engine *l_engine = new ns_waflz::engine();
                int32_t l_s;
                l_s = l_engine->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_engine->init_post_fork();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::instances *l_ix;
                ns_waflz::instance *l_i = NULL;
                l_ix = new ns_waflz::instances(*l_engine);
                REQUIRE((l_ix != NULL));
                l_s = l_ix->init_dbs();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_ix->load_config(&l_i, WAF_CONF_1001_JSON, sizeof(WAF_CONF_1001_JSON), true, false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_i != NULL));
                REQUIRE((l_i->get_id() == "1001"));
                l_engine->finalize();
                // -----------------------------------------
                // get instance
                // -----------------------------------------
                l_i = NULL;
                l_i = l_ix->get_instance("1001");
                REQUIRE((l_i != NULL));
                REQUIRE((l_i->get_id() == "1001"));
                // -----------------------------------------
                // verify update fail
                // -----------------------------------------
                l_s = l_ix->load_config(&l_i, WAF_CONF_1002_JSON, sizeof(WAF_CONF_1002_JSON), true, true);
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
                // -----------------------------------------
                // verify update success
                // -----------------------------------------
                l_s = l_ix->load_config(&l_i, WAF_CONF_1001_JSON, sizeof(WAF_CONF_1001_JSON), true, true);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // process
                // -----------------------------------------
                waflz_pb::event *l_event = NULL;
                std::string l_id("1001");
                l_i = l_ix->get_instance(l_id);
                l_ix->set_locking(true);
                REQUIRE((l_i != NULL));
                REQUIRE((l_i->get_id() == "1001"));
                ns_waflz::rqst_ctx::s_get_rqst_query_str_cb = get_rqst_query_str_long_cb;
                for(int i = 0; i < 2; ++i)
                {
                        int32_t l_s;
                        void *l_ctx = NULL;
                        if(i == 0)
                        {
                                l_s = l_ix->process_audit(&l_event, l_ctx, l_id);
                                if(l_event)
                                {
                                        delete l_event;
                                        l_event = NULL;
                                }
                        }
                        else if(i == 1)
                        {
                                l_s = l_ix->process_prod(&l_event, l_ctx, l_id);
                                if(l_event)
                                {
                                        delete l_event;
                                        l_event = NULL;
                                }
                        }

                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                }
                // -----------------------------------------
                // load configs tests with
                // last_modified_date
                // -----------------------------------------
                // -----------------------------------------
                // load with last_modified_date
                // -----------------------------------------
                l_s = l_ix->load_config(&l_i, WAF_CONF_1001_W_LM_DATE_JSON, sizeof(WAF_CONF_1001_W_LM_DATE_JSON), true, false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_i != NULL));
                REQUIRE((l_i->get_id() == "1001"));
                REQUIRE((l_i->get_pb()->last_modified_date() == "2016-07-20T00:45:20.744583Z"));
                // -----------------------------------------
                // load with new last_modified_date
                // -----------------------------------------
                l_s = l_ix->load_config(&l_i, WAF_CONF_1001_W_NEW_LM_DATE_JSON, sizeof(WAF_CONF_1001_W_NEW_LM_DATE_JSON), true, true);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_i != NULL));
                REQUIRE((l_i->get_id() == "1001"));
                REQUIRE((l_i->get_pb()->last_modified_date() == "2016-08-25T00:45:20.744583Z"));
                // -----------------------------------------
                // load with old last_modified_date
                // -----------------------------------------
                l_s = l_ix->load_config(&l_i, WAF_CONF_1001_W_LM_DATE_JSON, sizeof(WAF_CONF_1001_W_LM_DATE_JSON), true, true);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_i != NULL));
                REQUIRE((l_i->get_id() == "1001"));
                REQUIRE((l_i->get_pb()->last_modified_date() == "2016-08-25T00:45:20.744583Z"));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                l_engine->shutdown();
                if(l_ix)
                {
                        delete l_ix;
                        l_ix = NULL;
                }
                if(l_event)
                {
                        delete l_event;
                        l_event = NULL;
                }
                if(l_engine)
                {
                        delete l_engine;
                        l_engine = NULL;
                }
        }
}
