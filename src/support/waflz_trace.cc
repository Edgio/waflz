//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    waflz_trace.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    04/15/2016
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
#if 0
#include "trace_internal.h"
#include "time_util.h"
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: Statics
//: ----------------------------------------------------------------------------
trc_log_level_t s_trc_log_level = TRC_LOG_LEVEL_ERROR;
FILE* s_trc_log_file = stdout;
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void trc_log_print(trc_log_level_t a_level,
                   const char *a_file,
                   const char *a_func,
                   uint32_t a_line,
                   const char *a_format, ...)
{
        if(s_trc_log_file &&
           (s_trc_log_level >= a_level))
        {
                fprintf(s_trc_log_file, "%.3f %s %s:%s.%d: ",
                        ((double)get_time_ms())/1000.0,
                        trc_log_level_str(a_level),
                        a_file, a_func, a_line);
                va_list l_args;
                va_start(l_args, a_format);
                vfprintf(s_trc_log_file, a_format, l_args);
                va_end(l_args);
                fflush(s_trc_log_file);
        }
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void trc_log_level_set(trc_log_level_t a_level)
{
        s_trc_log_level = a_level;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t trc_log_file_open(const std::string &a_file)
{
        // WARNING DON'T USE TRC MACROS HERE'S -WILL BE RECURSIVE
        s_trc_log_file = fopen(a_file.c_str(), "a");
        if(!s_trc_log_file)
        {
                printf("Error opening trace logging file: %s. Reason: %s\n",
                                a_file.c_str(),
                                strerror(errno));
                return -1;
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t trc_log_file_close(void)
{
        int l_s;
        l_s = fclose(s_trc_log_file);
        if(l_s != 0)
        {
                printf("Error closing trace logging file: %p. Reason: %s\n",
                                s_trc_log_file,
                                strerror(errno));
                return -1;
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#ifndef ARRAY_SIZE
  #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
#ifndef ELEM_AT
  #define ELEM_AT(a, i, v) ((unsigned int) (i) < ARRAY_SIZE(a) ? (a)[(i)] : (v))
#endif
static const char *s_trc_log_level_strs[] =
{
#define XX(num, name, string) #string,
        TRC_LOG_LEVEL_MAP(XX)
#undef XX
};
const char *trc_log_level_str(trc_log_level_t a_level)
{
        return ELEM_AT(s_trc_log_level_strs, a_level, "?");
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void trc_mem_display(FILE *a_file, const uint8_t* a_mem_buf, uint32_t a_length)
{
        char l_display_line[256] = "";
        unsigned int l_bytes_displayed = 0;
        char l_byte_display[8] = "";
        char l_ascii_display[17]="";
        while (l_bytes_displayed < a_length)
        {
                unsigned int l_col = 0;
                snprintf(l_display_line, sizeof(l_display_line), "0x%08X ", l_bytes_displayed);
                strcat(l_display_line, " ");
                while ((l_col < 16) && (l_bytes_displayed < a_length))
                {
                        snprintf(l_byte_display, sizeof(l_byte_display), "%02X", (unsigned char) a_mem_buf[l_bytes_displayed]);
                        strcat(l_display_line, l_byte_display);
                        if (isprint(a_mem_buf[l_bytes_displayed]))
                                l_ascii_display[l_col] = a_mem_buf[l_bytes_displayed];
                        else
                                l_ascii_display[l_col] = '.';
                        l_col++;
                        l_bytes_displayed++;
                        if (!(l_col % 4))
                                strcat(l_display_line, " ");
                }
                if ((l_col < 16) && (l_bytes_displayed >= a_length))
                {
                        while (l_col < 16)
                        {
                                strcat(l_display_line, "..");
                                l_ascii_display[l_col] = '.';
                                l_col++;
                                if (!(l_col % 4))
                                        strcat(l_display_line, " ");
                        }
                }
                l_ascii_display[l_col] = '\0';
                strcat(l_display_line, " ");
                strcat(l_display_line, l_ascii_display);
                fprintf(a_file, "%s\n", l_display_line);
        }
}
} // namespace ns_waflz {
#endif
