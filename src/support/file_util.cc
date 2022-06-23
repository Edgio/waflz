//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! Includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "file_util.h"
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
//! ----------------------------------------------------------------------------
//! Macros
//! ----------------------------------------------------------------------------
#define FILE_UTIL_ERR_LEN 4096
#define FILE_UTIL_PERROR(...) do { \
                snprintf(ns_waflz::g_err_msg, FILE_UTIL_ERR_LEN, __VA_ARGS__); \
        }while(0)
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! Globals
//! ----------------------------------------------------------------------------
static char g_err_msg[FILE_UTIL_ERR_LEN];
//! ----------------------------------------------------------------------------
//! utils
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \brief   Read file into buffer
//! \details Reads file at a_file into buffer object up to a_max_file_size
//! \return  0 on Success
//!          -1 on Failure
//! \param   a_file: file to read from
//! \param   ao_buf: reference to buffer object to write into
//! \param   ao_len: file length (returned)
//! ----------------------------------------------------------------------------
int32_t read_file(const char *a_file, char **ao_buf, uint32_t &ao_len)
{
        FILE_UTIL_PERROR("none");
        // Check is a file
        struct stat l_stat;
        int32_t l_s = 0;
        l_s = stat(a_file, &l_stat);
        if(l_s != 0)
        {
                FILE_UTIL_PERROR("Error performing stat on file: %s  Reason: %s",
                                 a_file, strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        // Check if is regular file
        if(!(l_stat.st_mode & S_IFREG))
        {
                FILE_UTIL_PERROR("Error opening file: %s  Reason: is NOT a regular file",
                                 a_file);
                return WAFLZ_STATUS_ERROR;
        }
        // Open file...
        FILE * l_file;
        l_file = fopen(a_file,"r");
        if (NULL == l_file)
        {
                FILE_UTIL_PERROR("Error opening file: %s  Reason: %s",
                                 a_file, strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        // Read in file...
        int32_t l_size = l_stat.st_size;
        *ao_buf = (char *)malloc(sizeof(char)*l_size);
        ao_len = l_size;
        int32_t l_read_size;
        l_read_size = fread(*ao_buf, 1, l_size, l_file);
        if(l_read_size != l_size)
        {
                FILE_UTIL_PERROR("Error performing fread.  Reason: %s [%d:%d]\n",
                                 strerror(errno), l_read_size, l_size);
                return WAFLZ_STATUS_ERROR;
        }
        // Close file...
        l_s = fclose(l_file);
        if (0 != l_s)
        {
                FILE_UTIL_PERROR("Error performing fclose.  Reason: %s\n", strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \brief   write contents of buffer to the file
//! \details writes contents of a_buf to a_file
//! \return  0 on Success
//!          -1 on Failure
//! \param   a_file: file to read from
//! \param   ao_buf: reference to buffer object to write into
//! \param   ao_len: file length (returned)
//! ----------------------------------------------------------------------------
int32_t write_file(const char *a_file, char *a_buf, int32_t a_len)
{
        // Open file...
        int32_t l_s;
        FILE * l_file;
        l_file = fopen(a_file,"w");
        if (NULL == l_file)
        {
                FILE_UTIL_PERROR("Error opening file: %s  Reason: %s",
                                 a_file, strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }

        int32_t l_write_size;
        l_write_size = fwrite(a_buf, 1, a_len, l_file);
        if(l_write_size != a_len)
        {
                FILE_UTIL_PERROR("Error performing fwrite.  Reason: %s [%d:%d]\n",
                                 strerror(errno), l_write_size, a_len);
                return WAFLZ_STATUS_ERROR;
        }
        // Close file...
        l_s = fclose(l_file);
        if (0 != l_s)
        {
                FILE_UTIL_PERROR("Error performing fclose.  Reason: %s\n", strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Writes data from a_buffer into tmp file with prefix a_prefix
//! \return  0 on Success
//!          -1 on Failure
//! \param   a_buffer: buffer object to write into tmp file with
//! \param   a_prefix: prefix to use for naming tmp file
//! \param   ao_tmp_file_name: Name of tmp file created (including path)
//! ----------------------------------------------------------------------------
int32_t write_tmp(const char *a_prefix,
                  const char *a_buf,
                  uint32_t a_len,
                  std::string &ao_tmp_file_name)
{
        char l_temp_path[1024];
        snprintf(l_temp_path, 1024, "/tmp/%s-XXXXXX", a_prefix);
        int l_fd;
        l_fd = ::mkstemp(l_temp_path);
        ao_tmp_file_name = l_temp_path;
        if(l_fd == -1)
        {
                // failed to open temp file
                FILE_UTIL_PERROR("Reason: Failed to create temp file with path: %s: %s\n",
                                 l_temp_path,
                                 strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        uint32_t l_written = 0;
        uint32_t l_left = a_len;
        do {
                int l_wrote = 0;
                l_wrote = ::write(l_fd, &(a_buf[l_written]), l_left);
                if(l_wrote > 0)
                {
                        l_left -= (uint32_t)l_wrote;
                        l_written += (uint32_t)l_wrote;
                }
                else if(errno == EAGAIN)
                {
                        continue;
                }
                else
                {
                        FILE_UTIL_PERROR("Error performing write. Reason: %s\n",
                                         strerror(errno));
                        ::close(l_fd);
                        l_fd = -1;
                        return WAFLZ_STATUS_ERROR;
                }
        } while(l_left);
        ::close(l_fd);
        l_fd = -1;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Get last error
//! \return:  Last error reason
//! ----------------------------------------------------------------------------
const char * get_err_msg(void)
{
        return g_err_msg;
}
}
