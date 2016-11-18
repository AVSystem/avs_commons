/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifdef AVS_UNIT_TESTING
#define _BSD_SOURCE /* for mkstemp */
#endif

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include <limits.h>

#include <avsystem/commons/stream/stream_file.h>
#include <avsystem/commons/stream_v_table.h>

#define MODULE_NAME avs_stream
#include <x_log_config.h>

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

struct avs_file_stream_struct {
    const void *const vtable;
    uint8_t mode;
    int error_code;
    FILE *fp;
};

int avs_stream_file_length(avs_stream_abstract_t *stream,
                           avs_off_t *out_length) {
    const avs_stream_v_table_extension_file_t *ext =
            (const avs_stream_v_table_extension_file_t *)
            avs_stream_v_table_find_extension(stream,
                                              AVS_STREAM_V_TABLE_EXTENSION_FILE);
    if (ext) {
        return ext->length(stream, out_length);
    }
    return -1;
}

int avs_stream_file_offset(avs_stream_abstract_t *stream,
                           avs_off_t *out_offset) {
    const avs_stream_v_table_extension_file_t *ext =
            (const avs_stream_v_table_extension_file_t *)
            avs_stream_v_table_find_extension(stream,
                                              AVS_STREAM_V_TABLE_EXTENSION_FILE);
    if (ext) {
        return ext->offset(stream, out_offset);
    }
    return -1;
}

int avs_stream_file_seek(avs_stream_abstract_t *stream,
                         avs_off_t offset_from_start) {
    const avs_stream_v_table_extension_file_t *ext =
            (const avs_stream_v_table_extension_file_t *)
            avs_stream_v_table_find_extension(stream,
                                              AVS_STREAM_V_TABLE_EXTENSION_FILE);
    if (ext) {
        return ext->seek(stream, offset_from_start);
    }
    return -1;
}

static int stream_file_write(avs_stream_abstract_t *stream_,
                             const void *buffer,
                             size_t buffer_length) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream_;
    size_t written;
    if ((file->mode & AVS_STREAM_FILE_WRITE) == 0) {
        file->error_code = EBADF;
        return -1;
    }
    written = fwrite(buffer, 1, buffer_length, file->fp);
    if (ferror(file->fp) || written != buffer_length) {
        file->error_code = EIO;
        return -1;
    }
    file->error_code = 0;
    return 0;
}

static int stream_file_read(avs_stream_abstract_t *stream_,
                            size_t *out_bytes_read,
                            char *out_message_finished,
                            void *buffer,
                            size_t buffer_length) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream_;
    if ((file->mode & AVS_STREAM_FILE_READ) == 0) {
        file->error_code = EBADF;
        return -1;
    }
    *out_bytes_read = fread(buffer, 1, buffer_length, file->fp);
    if (ferror(file->fp)) {
        file->error_code = EIO;
        return -1;
    }
    if (out_message_finished) {
        *out_message_finished = !!feof(file->fp);
    }
    file->error_code = 0;
    return 0;
}

static int stream_file_peek(avs_stream_abstract_t *stream_,
                            size_t offset) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream_;
    int8_t byte = EOF;
    size_t bytes_read;
    char message_finished;
    avs_off_t current;

    if (offset > LONG_MAX) {
        file->error_code = ERANGE;
        return -1;
    }
    current = ftell(file->fp);
    if (fseek(file->fp, (long) offset, SEEK_CUR)) {
        file->error_code = EIO;
        return -1;
    }

    if (stream_file_read(stream_, &bytes_read, &message_finished,
                         (char *) &byte, 1)) {
        return -1;
    }

    if (fseek(file->fp, current, SEEK_SET)) {
        file->error_code = EIO;
        return -1;
    }
    file->error_code = 0;
    return (int) byte;
}

static int stream_file_reset(avs_stream_abstract_t *stream_) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream_;
    clearerr(file->fp);
    if (fseek(file->fp, 0, SEEK_SET)) {
        file->error_code = EIO;
        return -1;
    }
    file->error_code = 0;
    return 0;
}

static int stream_file_errno(avs_stream_abstract_t *stream_) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream_;
    return file->error_code;
}

static int stream_file_close(avs_stream_abstract_t *stream_) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream_;
    return fclose(file->fp) ? -1 : 0;
}

static int unimplemented() {
    return -1;
}

static int stream_file_offset(avs_stream_abstract_t *stream,
                              avs_off_t *out_offset) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream;
    avs_off_t offset = ftell(file->fp);
    if (offset == -1) {
        file->error_code = EIO;
        return -1;
    }
    file->error_code = 0;
    *out_offset = offset;
    return 0;
}

static int stream_file_seek(avs_stream_abstract_t *stream,
                            avs_off_t offset_from_start) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream;
    if (offset_from_start < 0) {
        file->error_code = ERANGE;
        return -1;
    }
    if (fseek(file->fp, offset_from_start, SEEK_SET)) {
        file->error_code = EIO;
        return -1;
    }
    file->error_code = 0;
    return 0;
}

static int stream_file_length(avs_stream_abstract_t *stream,
                              avs_off_t *out_length) {
    avs_stream_file_t *file = (avs_stream_file_t *) stream;
    avs_off_t offset;
    if (stream_file_offset(stream, &offset)) {
        return -1;
    }
    if (fseek(file->fp, 0, SEEK_END) || stream_file_offset(stream, out_length)) {
        stream_file_seek(stream, offset);
        file->error_code = EIO;
        return -1;
    }
    return stream_file_seek(stream, offset);
}

static const avs_stream_v_table_extension_file_t stream_file_ext_vtable = {
    stream_file_length,
    stream_file_offset,
    stream_file_seek
};

static const avs_stream_v_table_extension_t stream_file_extensions[] = {
    { AVS_STREAM_V_TABLE_EXTENSION_FILE, &stream_file_ext_vtable },
    AVS_STREAM_V_TABLE_EXTENSION_NULL
};

static const avs_stream_v_table_t file_stream_vtable = {
    stream_file_write,
    (avs_stream_finish_message_t) unimplemented,
    stream_file_read,
    stream_file_peek,
    stream_file_reset,
    stream_file_close,
    stream_file_errno,
    stream_file_extensions
};

avs_stream_abstract_t *
avs_stream_file_create(const char *path,
                       uint8_t mode) {
    avs_stream_file_t *file =
        (avs_stream_file_t *) calloc(1, sizeof(avs_stream_file_t));
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
    return (avs_stream_abstract_t *) file;
error:
    free(file);
    return NULL;
}

#ifdef AVS_UNIT_TESTING
#include "test/test_stream_file.c"
#endif
