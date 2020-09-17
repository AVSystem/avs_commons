/*
 * Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define AVS_STREAM_STREAM_FILE_C
#include <avs_commons_init.h>

#ifdef AVS_COMMONS_STREAM_WITH_FILE

#    include <assert.h>
#    include <errno.h>
#    include <limits.h>
#    include <stdarg.h>
#    include <string.h>

#    include <avsystem/commons/avs_errno_map.h>
#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_stream_file.h>
#    include <avsystem/commons/avs_stream_v_table.h>

#    define MODULE_NAME avs_stream
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

struct avs_file_stream_struct {
    const void *const vtable;
    uint8_t mode;
    FILE *fp;
};

avs_error_t avs_stream_file_length(avs_stream_t *stream,
                                   avs_off_t *out_length) {
    const avs_stream_v_table_extension_file_t *ext =
            (const avs_stream_v_table_extension_file_t *)
                    avs_stream_v_table_find_extension(
                            stream, AVS_STREAM_V_TABLE_EXTENSION_FILE);
    if (ext) {
        return ext->length(stream, out_length);
    }
    return avs_errno(AVS_ENOTSUP);
}

avs_error_t avs_stream_file_seek(avs_stream_t *stream,
                                 avs_off_t offset_from_start) {
    const avs_stream_v_table_extension_file_t *ext =
            (const avs_stream_v_table_extension_file_t *)
                    avs_stream_v_table_find_extension(
                            stream, AVS_STREAM_V_TABLE_EXTENSION_FILE);
    if (ext) {
        return ext->seek(stream, offset_from_start);
    }
    return avs_errno(AVS_ENOTSUP);
}

static avs_error_t stream_file_write_some(avs_stream_t *stream_,
                                          const void *buffer,
                                          size_t *inout_data_length) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream_;
    if ((file->mode & AVS_STREAM_FILE_WRITE) == 0) {
        return avs_errno(AVS_EBADF);
    }
    *inout_data_length = fwrite(buffer, 1, *inout_data_length, file->fp);
    if (ferror(file->fp)) {
        return avs_errno(AVS_EIO);
    }
    return AVS_OK;
}

static avs_error_t stream_file_read(avs_stream_t *stream_,
                                    size_t *out_bytes_read,
                                    bool *out_message_finished,
                                    void *buffer,
                                    size_t buffer_length) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream_;
    if ((file->mode & AVS_STREAM_FILE_READ) == 0) {
        return avs_errno(AVS_EBADF);
    }
    size_t bytes_read = fread(buffer, 1, buffer_length, file->fp);
    if (out_bytes_read) {
        *out_bytes_read = bytes_read;
    }
    if (ferror(file->fp)) {
        return avs_errno(AVS_EIO);
    }
    if (out_message_finished) {
        *out_message_finished = !!feof(file->fp);
    }
    return AVS_OK;
}

static avs_error_t
stream_file_peek(avs_stream_t *stream_, size_t offset, char *out_value) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream_;
    size_t bytes_read;
    bool message_finished;
    avs_off_t current;

    if (offset > LONG_MAX) {
        return avs_errno(AVS_ERANGE);
    }

    current = ftell(file->fp);
    if (current < 0) {
        avs_errno_t err = avs_map_errno(errno);
        if (!err) {
            err = AVS_UNKNOWN_ERROR;
        }
        return avs_errno(err);
    }

    if (fseek(file->fp, (long) offset, SEEK_CUR)) {
        return avs_errno(AVS_EIO);
    }

    avs_error_t err = stream_file_read(stream_, &bytes_read, &message_finished,
                                       out_value, 1);
    if (avs_is_err(err)) {
        return err;
    }

    if (fseek(file->fp, current, SEEK_SET)) {
        return avs_errno(AVS_EIO);
    }
    return bytes_read >= 1 ? AVS_OK : AVS_EOF;
}

static avs_error_t stream_file_reset(avs_stream_t *stream_) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream_;
    clearerr(file->fp);
    if (fseek(file->fp, 0, SEEK_SET)) {
        return avs_errno(AVS_EIO);
    }
    return AVS_OK;
}

static avs_error_t stream_file_close(avs_stream_t *stream_) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream_;
    return avs_errno(fclose(file->fp) ? AVS_EIO : AVS_NO_ERROR);
}

static avs_error_t stream_file_offset(avs_stream_t *stream,
                                      avs_off_t *out_offset) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream;
    avs_off_t offset = ftell(file->fp);
    if (offset == -1) {
        return avs_errno(AVS_EIO);
    }
    *out_offset = offset;
    return AVS_OK;
}

static avs_error_t stream_file_seek(avs_stream_t *stream,
                                    avs_off_t offset_from_start) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream;
    if (offset_from_start < 0) {
        return avs_errno(AVS_ERANGE);
    }
    if (fseek(file->fp, offset_from_start, SEEK_SET)) {
        return avs_errno(AVS_EIO);
    }
    return AVS_OK;
}

static avs_error_t stream_file_length(avs_stream_t *stream,
                                      avs_off_t *out_length) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream;
    avs_off_t offset;
    avs_error_t err = stream_file_offset(stream, &offset);
    if (avs_is_err(err)) {
        return err;
    }
    if (fseek(file->fp, 0, SEEK_END)) {
        err = avs_errno(AVS_EIO);
    }
    if (avs_is_ok(err)) {
        err = stream_file_offset(stream, out_length);
    }
    avs_error_t seek_err = stream_file_seek(stream, offset);
    return avs_is_ok(err) ? seek_err : err;
}

static const avs_stream_v_table_t file_stream_vtable = {
    .write_some = stream_file_write_some,
    .read = stream_file_read,
    .peek = stream_file_peek,
    .reset = stream_file_reset,
    .close = stream_file_close,
    .extension_list =
            (const avs_stream_v_table_extension_t[]) {
                    { AVS_STREAM_V_TABLE_EXTENSION_OFFSET,
                      &(const avs_stream_v_table_extension_offset_t) {
                              stream_file_offset } },
                    { AVS_STREAM_V_TABLE_EXTENSION_FILE,
                      &(const avs_stream_v_table_extension_file_t) {
                              stream_file_length, stream_file_seek } },
                    AVS_STREAM_V_TABLE_EXTENSION_NULL }
};

avs_stream_t *avs_stream_file_create(const char *path, uint8_t mode) {
    avs_stream_file_t *file =
            (avs_stream_file_t *) avs_calloc(1, sizeof(avs_stream_file_t));
    const void *vtable = &file_stream_vtable;
    if (!file) {
        goto error;
    }
    memcpy((void *) (intptr_t) &file->vtable, &vtable, sizeof(void *));

    if (mode == (AVS_STREAM_FILE_READ | AVS_STREAM_FILE_WRITE)) {
        file->fp = fopen(path, "w+b");
    } else if (mode == AVS_STREAM_FILE_READ) {
        file->fp = fopen(path, "rb");
    } else if (mode == AVS_STREAM_FILE_WRITE) {
        file->fp = fopen(path, "wb");
    } else {
        goto error;
    }

    if (!file->fp) {
        goto error;
    }
    file->mode = mode;
    return (avs_stream_t *) file;
error:
    avs_free(file);
    return NULL;
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/stream/test_stream_file.c"
#    endif

#endif // AVS_COMMONS_STREAM_WITH_FILE
