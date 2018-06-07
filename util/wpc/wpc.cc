//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wpc.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    01/18/2018
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
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <string>
#include <vector>
#include "support/ndebug.h"
#include "waf_config.pb.h"
#include "rl.pb.h"
#include "jspb/jspb.h"
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#ifndef UNUSED
#define UNUSED(x) ( (void)(x) )
#endif

//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
struct _pb_header {
        // -------------------------------------------------
        // type
        // -------------------------------------------------
        typedef enum {
                TYPE_UNKNOWN            = 0x0000,
                TYPE_WAF_EVENT          = 0x0007,
                TYPE_RATE_LIMITING_EVENT= 0x0008,
                _TYPE_MAX = 0xffff,
        } type_t;
        // -------------------------------------------------
        // checksum
        // -------------------------------------------------
        typedef enum {
                CHECKSUM_NONE = 0,
                CHECKSUM_XOR_HEADER = 1,
                CHECKSUM_CITY_HASH = 2,
                _CHECKSUM_MAX = 63,
        } checksum_type_t;
        // -------------------------------------------------
        // encoding
        // -------------------------------------------------
        typedef enum {
                ENCODING_NONE = 0,
                ENCODING_SNAPPY = 1,
                ENCODING_JSON = 2,
                _ENCODING_MAX = 1023,
        } encoding_t;
        // -------------------------------------------------
        // members
        // -------------------------------------------------
        type_t m_type:16;
        checksum_type_t m_checksum_type:6;
        encoding_t m_encoding:10;
        uint32_t m_length;
        uint32_t m_checksum;
        uint32_t m_reserved;
} __attribute__((packed));
typedef struct _pb_header pb_header_t;
//: ----------------------------------------------------------------------------
//: \details Parse and print a protobuf from a given
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
template <typename _Tp>
int print_protobuf(_Tp& ao_pb,
                   char *a_buf,
                   uint32_t a_buf_len,
                   bool a_print_short,
                   bool a_print_json)
{
        bool l_pb_s;
        l_pb_s = ao_pb.ParseFromArray(a_buf, a_buf_len);
        if(!l_pb_s)
        {
                fprintf(stderr, "WARNING: failed to parse protobuf with length: %u\n", a_buf_len);
                return -1;
        }
        if (a_print_json)
        {
                std::string l_str;
                int l_s;
                l_s = ns_jspb::convert_to_json(l_str, ao_pb);
                if(l_s != JSPB_OK)
                {
                        fprintf(stderr, "WARNING: failed to convert protobuf to json\n");
                }
                fprintf(stdout, "%s\n", l_str.c_str());
        }
        else if (a_print_short)
        {
                fprintf(stdout, "%s\n", ao_pb.ShortDebugString().c_str());
        }
        else
        {
                fprintf(stdout, "%s\n", ao_pb.DebugString().c_str());
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: \details Print Version info to stream with exit code
//: \return  NA
//: \param   stream: Where to write version info (eg sterr/stdout)
//: \param   exit_code: Exit with return code
//: ----------------------------------------------------------------------------
void print_version(FILE* stream, int exit_code)
{
        // print out the version information
        fprintf(stream, "waflz protocol buffer cat (wpc).\n");
        fprintf(stream, "Copyright (C) Verizon Digital Media Services.\n");
        exit(exit_code);
}
//: ----------------------------------------------------------------------------
//: \details Display Help to user
//: \return  NA
//: \param   stream: Where to write version info (eg sterr/stdout)
//: \param   exit_code: Exit with return code
//: ----------------------------------------------------------------------------
void print_usage(FILE* stream, int exit_code)
{
        fprintf(stream, "Usage: wpc [OPTIONS]\n");
        fprintf(stream, "waflz protocol buffer cat (wpc) -from stdin.\n");
        fprintf(stream, "\n");
        fprintf(stream, "Options:\n");
        fprintf(stream, "  -h, --help      Display this help and exit\n");
        fprintf(stream, "  -v, --version   Display the version number and exit\n");
        fprintf(stream, "  -d, --debug     Debug output [Default: OFF]\n");
        fprintf(stream, "  -s, --short     Short output\n");
        fprintf(stream, "  -j, --json      JSON output\n");
        fprintf(stream, "  -n, --number    Print first N\n");
        fprintf(stream, "  -t, --tolerant  Tolerant of malformed headers/pbufs\n");
        exit(exit_code);
}
//: ----------------------------------------------------------------------------
//: \details main entry point
//: \return  0 on Success
//:          -1 on Failure
//: \param   argc/argv See usage...
//: ----------------------------------------------------------------------------
int main(int argc, char** argv)
{
        char l_opt;
        std::string l_arg;
        int l_option_index = 0;
        // config
        bool l_cfg_debug = false;
        bool l_cfg_short = false;
        bool l_cfg_json = false;
        int32_t l_cfg_num = -1;
        bool l_cfg_tolerant = false;
        struct option l_long_options[] =
        {
                { "help",        0, 0, 'h' },
                { "version",     0, 0, 'v' },
                { "debug",       0, 0, 'd' },
                { "short",       0, 0, 's' },
                { "json",        0, 0, 'j' },
                { "number",      0, 0, 'n' },
                { "tolerant",    0, 0, 't' },

                // list sentinel
                { 0, 0, 0, 0 }
        };
        while ((l_opt = getopt_long_only(argc,
                                         argv,
                                         "hvdsjn:t",
                                         l_long_options,
                                         &l_option_index)) != -1)
        {
                if (optarg)
                {
                        l_arg = std::string(optarg);
                }
                else
                {
                        l_arg.clear();
                }
                switch(l_opt)
                {
                // -----------------------------------------
                // help
                // -----------------------------------------
                case 'h':
                {
                        print_usage(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // verion
                // -----------------------------------------
                case 'v':
                {
                        print_version(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // debug
                // -----------------------------------------
                case 'd':
                {
                        l_cfg_debug = true;
                        break;
                }
                // -----------------------------------------
                // short
                // -----------------------------------------
                case 's':
                {
                        l_cfg_short = true;
                        break;
                }
                // -----------------------------------------
                // json
                // -----------------------------------------
                case 'j':
                {
                        l_cfg_json = true;
                        break;
                }
                // -----------------------------------------
                // number
                // -----------------------------------------
                case 'n':
                {
                        l_cfg_num = true;
                        break;
                }
                // -----------------------------------------
                // tolerant
                // -----------------------------------------
                case 't':
                {
                        l_cfg_tolerant = true;
                        break;
                }
                // -----------------------------------------
                // what?
                // -----------------------------------------
                case '?':
                {
                        print_usage(stdout, -1);
                        break;
                }
                // -----------------------------------------
                // huh?
                // -----------------------------------------
                default:
                {
                        print_usage(stdout, -1);
                        break;
                }
                }
        }
        UNUSED(l_cfg_tolerant);
        // -------------------------------------------------
        // read from stdin
        // -------------------------------------------------
        int32_t l_pb_num = 0;
        uint32_t l_len = 0;
        char *l_buf = NULL;
        ssize_t l_rs;
        while(true)
        {
                pb_header_t l_hdr;
                // -----------------------------------------
                // read a header
                // -----------------------------------------
                l_len = sizeof(l_hdr);
                l_buf = (char *)&l_hdr;
                do {
                        l_rs = read(STDIN_FILENO, l_buf, l_len);
                        if((l_rs < 0) &&
                           (errno != EAGAIN))
                        {
                                fprintf(stderr, "error performing read: %s\n", strerror(errno));
                                return -1;
                        }
                        else if(l_rs == 0)
                        {
                                return 0;
                        }
                        l_buf += l_rs;
                        l_len -= l_rs;
                } while((l_rs != 0) && l_len);
                // -----------------------------------------
                // print header
                // -----------------------------------------
                if(l_cfg_debug)
                {
                        printf("+-------------------------------+\n");
                        printf(":          H E A D E R          :\n");
                        printf("+-------------------------------+\n");
                        printf(": type:          0x%08X\n", l_hdr.m_type);
                        printf(": checksum_type: 0x%08X\n", l_hdr.m_checksum_type);
                        printf(": encoding:      0x%08X\n", l_hdr.m_encoding);
                        printf(": length:        0x%08X\n", l_hdr.m_length);
                        printf(": checksum:      0x%08X\n", l_hdr.m_checksum);
                        printf(": reserved:      0x%08X\n", l_hdr.m_reserved);
                        printf("+-------------------------------+\n");
                }
                // -----------------------------------------
                // get size / alloc
                // -----------------------------------------
                if(l_hdr.m_length >= (1<<30))
                {
                        fprintf(stderr, "error protobuf length > 1G\n");
                        return -1;
                }
                // -----------------------------------------
                // read
                // -----------------------------------------
                char *l_pb_buf;
                l_pb_buf = (char *)malloc(l_hdr.m_length);
                l_buf = l_pb_buf;
                l_len = l_hdr.m_length;
                do {
                        l_rs = read(STDIN_FILENO, l_buf, l_len);
                        if((l_rs < 0) &&
                           (errno != EAGAIN))
                        {
                                fprintf(stderr, "error performing read: %s\n", strerror(errno));
                                return -1;
                        }
                        else if(l_rs == 0)
                        {
                                return 0;
                        }
                        l_buf += l_rs;
                        l_len -= l_rs;
                } while((l_rs != 0) && l_len);
                // -----------------------------------------
                // parse
                // -----------------------------------------
                switch (l_hdr.m_type)
                {
                // -----------------------------------------
                // waf
                // -----------------------------------------
                case _pb_header::TYPE_WAF_EVENT: {
                        waflz_pb::event l_e;
                        print_protobuf(l_e, l_pb_buf, l_hdr.m_length, l_cfg_short, l_cfg_json);
                        break;
                }
                // -----------------------------------------
                // rate-limiting
                // -----------------------------------------
                case _pb_header::TYPE_RATE_LIMITING_EVENT: {
                        waflz_pb::rl_event l_e;
                        print_protobuf(l_e, l_pb_buf, l_hdr.m_length, l_cfg_short, l_cfg_json);
                        break;
                }
                default:
                        fprintf(stderr, "error unknown header type: %02x\n", l_hdr.m_type);
                        return -1;
                }
                // -----------------------------------------
                // clean up
                // -----------------------------------------
                if(l_pb_buf)
                {
                        free(l_pb_buf);
                        l_pb_buf = NULL;
                }
                // -----------------------------------------
                // stop reading if num spec'd and >=
                // -----------------------------------------
                if((l_cfg_num > 0) &&
                   (l_pb_num >= l_cfg_num))
                {
                        break;
                }
        }
        return 0;
}
