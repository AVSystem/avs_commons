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

#ifndef AVS_COMMONS_CRYPTO_UTILS_H
#define AVS_COMMONS_CRYPTO_UTILS_H

#include <stddef.h>

#include <avsystem/commons/avs_crypto_pki.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

typedef enum {
    DATA_SOURCE_ELEMENT_END = 0,
    DATA_SOURCE_ELEMENT_STRING,
    DATA_SOURCE_ELEMENT_BUFFER
} avs_crypto_data_source_element_type_t;

typedef struct {
    avs_crypto_data_source_element_type_t type;
    size_t offset;
    size_t size_offset;
} avs_crypto_data_source_element_t;

typedef avs_error_t avs_crypto_security_info_iterate_cb_t(
        const avs_crypto_security_info_union_t *desc, void *arg);

avs_error_t
_avs_crypto_security_info_iterate(const avs_crypto_security_info_union_t *desc,
                                  avs_crypto_security_info_iterate_cb_t *cb,
                                  void *cb_arg);

const avs_crypto_data_source_element_t *
_avs_crypto_get_data_source_definition(avs_crypto_data_source_t source);

avs_error_t
_avs_crypto_calculate_info_stats(const avs_crypto_security_info_union_t *desc,
                                 avs_crypto_security_info_tag_t expected_type,
                                 size_t *out_element_count,
                                 size_t *out_data_buffer_size);

bool _avs_crypto_aead_parameters_valid(size_t key_len,
                                       size_t iv_len,
                                       size_t tag_len);

typedef enum { ENCODING_PEM, ENCODING_DER } _avs_crypto_cert_encoding_t;

_avs_crypto_cert_encoding_t _avs_crypto_detect_cert_encoding(const void *buffer,
                                                             size_t len);

VISIBILITY_PRIVATE_HEADER_END

#endif // AVS_COMMONS_CRYPTO_UTILS_H
