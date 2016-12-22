/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_STREAM_H
#define	AVS_COMMONS_STREAM_H

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

#include <avsystem/commons/defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @file stream.h
 *
 * Generic stream interface.
 *
 * All functions declared in this file operate on @ref avs_stream_abstract_t
 * which internally stores pointers to the implementations of the interface
 * methods (via @ref avs_stream_v_table_t). You can find sample stream
 * implementations in stream/src folder of the avs_commons source directory.
 *
 * Different kind of streams may have different functionality, and using some
 * methods may not make sense for every stream (for example writing to a
 * read-only stream). In such cases one can safely omit implementation of
 * unnecessary methods. Calling them will result in negative return value.
 *
 * Moreover, the interface may be extended with additional methods by using
 * @ref avs_stream_v_table_extension_t . Again, for sample implementation of
 * this technique see @file stream/src/stream_file.c .
 *
 * Errors are reported via return values of the interface methods. We assume
 * a negative value to indicate an error, and success otherwise. Additionally
 * implementations are allowed to set stream error code (queryable via @ref
 * avs_stream_errno) to provide more information about the occured error.
 */
struct avs_stream_abstract_struct;
typedef struct avs_stream_abstract_struct avs_stream_abstract_t;

/**
 * Writes data to the stream by calling @ref avs_stream_vtable_t#write method
 * on the underlying stream. Implementation MUST fail if less than
 * @p buffer_length bytes were successfully written.
 *
 * @param stream        Stream to write data to.
 * @param buffer        Data to write, MUST NOT be NULL.
 * @param buffer_length Amount of bytes to write.
 *
 * @returns 0 on success, negative value on error.
 */
int avs_stream_write(avs_stream_abstract_t *stream,
                     const void *buffer,
                     size_t buffer_length);

/**
 * Finishes the message written onto stream by calling
 * @ref avs_stream_vtable_t#finish_message. The underlying stream may freely
 * define its functionality in a implementation specific way.
 *
 * For example, on some kind of network stream, message finish may cause
 * packet serialization and issuing @ref send() .
 *
 * @param stream    Stream to operate on.
 *
 * @returns 0 on success, negative value on error.
 */
int avs_stream_finish_message(avs_stream_abstract_t *stream);

/**
 * Helper function that writes formatted message onto the stream by calling
 * @ref avs_stream_vtable_t#write method on the underlying stream.
 *
 * Format specifiers are the same as @ref printf format specifiers.
 *
 * @param stream    Stream to operate on.
 * @param msg       Message format string.
 * @param ...       Message format string arguments (as in @ref printf).
 *
 * @return 0 on success, negative value on error.
 */
int avs_stream_write_f(avs_stream_abstract_t *stream,
                       const char *msg, ...) AVS_F_PRINTF(2, 3);

/**
 * Works similarly as @ref avs_stream_write_f except that format string
 * arguments are specified via va_list.
 *
 * @param stream    Stream to operate on.
 * @param msg       Message format string.
 * @param args      Message format string arguments.
 *
 * @return 0 on succes, negative value on error.
 */
int avs_stream_write_fv(avs_stream_abstract_t *stream,
                        const char *msg,
                        va_list args);

/**
 * Reads up to @p buffer_length bytes from the stream by calling
 * @ref avs_stream_v_table##read on the underlying stream implementation.
 *
 * @p out_message_finished parameter value indicates whether a logical message
 * (where "logical" may have different meaning in context of different streams)
 * has been read entirely. @p out_message_finished set to 1 however does not
 * imply that no more messages are or will be available.
 *
 * For example, let's consider an HTTP client implemented as a stream. Logical
 * message could correspond with an HTTP response entity. After reading it
 * entirely, it may be possible to issue another request via the same stream and
 * read response to it afterwards.
 *
 * Another example, illustrating a slightly different interpretation of the
 * message finished semantics may be a file stream. It would make sense then
 * to set @p out_message_finished to 1 if the entire file has been read and 0
 * otherwise.
 *
 * Note: this function will never read 0 bytes and set @p out_message_finished to
 * 0 at the same time.
 *
 * Note: even if the final outcome of the read operation is an error, it is still
 * possible that some data was written into the @p buffer.
 *
 * @param stream                Stream to operate on.
 * @param out_bytes_read        Pointer to a variable where amount of read bytes
 *                              will be written, or NULL.
 * @param out_message_finished  Pointer to a variable where information about
 *                              message state will be stored (0 if not finished,
 *                              1 otherwise), or NULL.
 * @param buffer                Pointer to a memory block where read bytes shall
 *                              be stored.
 * @param buffer_length         Available buffer storage.
 *
 * @returns 0 on success, negative value on error.
 */
int avs_stream_read(avs_stream_abstract_t *stream,
                    size_t *out_bytes_read,
                    char *out_message_finished,
                    void *buffer,
                    size_t buffer_length);

/**
 * Attempts to read EXACTLY @p buffer_length bytes from the underlying stream
 * by calling @ref avs_stream_read (possibly multiple times).
 *
 * If it is not possible to read exactly @p buffer_length bytes an error is
 * returned (even though some chunk of the data might have been read into the @p
 * buffer).
 *
 * @param stream        Stream to operate on.
 * @param buffer        Pointer to a memory block where read bytes shall be
 *                      stored.
 * @param buffer_length Amount of bytes to read.
 *
 * @returns 0 on success, negative value on error.
 */
int avs_stream_read_reliably(avs_stream_abstract_t *stream,
                             void *buffer,
                             size_t buffer_length);

/**
 * Ignores stream data by calling @ref avs_stream_getch till the message is
 * finished. (For the more informative reference about "finished message" see
 * @ref avs_stream_read documentation).
 *
 * @param stream    Stream to operate on.
 * @returns 0 on success, negative value on error.
 */
int avs_stream_ignore_to_end(avs_stream_abstract_t *stream);

/**
 * Peeks a single byte at specified offset (from the current stream position),
 * without consuming it.
 *
 * Note: streams might not implement this functionality or they may set
 * arbitrary limit on the maximum supported @p offset value.
 *
 * @param stream    Stream to operate on.
 * @param offset    Offset from the current stream position.
 * @returns 0 on success, EOF if a character cannot be read, negative value
 * (different than EOF) in case of error.
 */
int avs_stream_peek(avs_stream_abstract_t *stream, size_t offset);

/**
 * Reads a single byte from the stream. Semantics of "message finished" is the
 * same as for @ref avs_stream_read (as it calls @ref avs_stream_read
 * underneath).
 *
 * @param stream                Stream to operate on.
 * @param out_message_finished  Pointer to a variable where information about
 *                              message state will be stored (0 if not finished,
 *                              1 otherwise), or NULL.
 *
 * @returns 0 on success, EOF if the message is finished, negative value
 * (different than EOF) on error.
 */
int avs_stream_getch(avs_stream_abstract_t *stream, char *out_message_finished);

/**
 * Helper function that reads a line (terminated with '\n' or '\r\n') from the
 * stream by calling @ref avs_stream_v_table_t#read (possibly multiple times) on
 * the underlying stream implementation.
 *
 * Note: unless an error during reading occured @p buffer will always be
 * NULL terminated.
 *
 * Note: the line terminator ('\n' or '\r\n') is never written into the
 * @p buffer.
 *
 * @param stream                Stream to operate on.
 * @param out_bytes_read        Pointer to a variable where amount of read bytes
 *                              will be written (excluding final NULL-terminator
 *                              added internally), or NULL.
 * @param out_message_finished  Pointer to a variable where information about
 *                              message state will be stored (0 if not finished,
 *                              1 otherwise), or NULL.
 * @param buffer                Pointer to a memory block where read line will
 *                              be written. Must not be NULL.
 * @param buffer_length         Number of bytes that can be stored in the buffer
 *                              (including storage for the NULL-terminator),
 *                              must NOT be 0.
 *
 * @returns
 * - 0 on success
 * - negative value on error (including when the line was not properly
 *   terminated)
 * - positive value if the line did not fit entirely into the @p buffer
 */
int avs_stream_getline(avs_stream_abstract_t *stream,
                       size_t *out_bytes_read,
                       char *out_message_finished,
                       char *buffer,
                       size_t buffer_length);

/**
 * Similar to @ref avs_stream_getline except that it does not consume stream
 * data.
 *
 * Note: this operation will be unavailable if @ref avs_stream_v_table_t#peek
 * method is not implemented. Also note that this function shares limitations
 * of @ref avs_stream_peek as it uses it internally.
 *
 * @param stream            Stream to operate on.
 * @param offset            Offset from the current stream position where line
 *                          peeking shall be started.
 * @param out_bytes_peeked  Pointer to a variable where amount of bytes written
 *                          into the buffer shall be stored (excluding final
 *                          NULL-terminator, added internally), or NULL.
 * @param out_next_offset   Pointer to a variable where offset where peeking
 *                          stopped (which is an @p offset + amount of bytes
 *                          written into the @p buffer + length of line
 *                          terminators if any) shall be stored, or NULL.
 * @param buffer            Pointer to the memory block where data will be
 *                          stored. Must NOT be NULL.
 * @param buffer_length     Number of bytes that can be stored in the buffer
 *                          (including storage for the NULL-terminator), MUST
 *                          not be 0.
 *
 * @returns
 * - 0 on success
 * - negative value on error (including when the line was not properly
 *   terminated)
 * - positive value if the line did not fit entirely into the @p buffer
 */
int avs_stream_peekline(avs_stream_abstract_t *stream,
                        size_t offset,
                        size_t *out_bytes_peeked,
                        size_t *out_next_offset,
                        char *buffer,
                        size_t buffer_length);
/**
 * Resets stream state (which is something highly dependend on the stream
 * implementation) by calling @ref avs_stream_v_table#reset method .
 *
 * @param stream    Stream to reset.
 * @returns 0 on success, negative value on error.
 */
int avs_stream_reset(avs_stream_abstract_t *stream);

/**
 * Calls @ref avs_stream_v_table#close on the underlying stream implementation,
 * and frees the @p *stream. After it is done @p *stream is set to NULL.
 *
 * Note: if @p *stream is NULL then no action is performed.
 *
 * @param stream    Pointer to the stream to cleanup.
 */
void avs_stream_cleanup(avs_stream_abstract_t **stream);

/**
 * Obtains additional information about last stream error by calling @ref
 * avs_stream_v_table#get_errno .
 *
 * @param stream    Stream to operate on.
 * @returns last error code or 0 if no error occurred.
 */
int avs_stream_errno(avs_stream_abstract_t *stream);

#ifdef	__cplusplus
}
#endif

#endif	/* STREAM_H */
