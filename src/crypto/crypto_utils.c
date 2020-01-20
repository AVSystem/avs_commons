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

#include <avs_commons_config.h>

#define MODULE_NAME avs_crypto
#include <x_log_config.h>

#include "crypto_utils.h"

VISIBILITY_SOURCE_BEGIN

bool _avs_crypto_aead_parameters_valid(size_t key_len,
                                       size_t iv_len,
                                       size_t tag_len) {
    if (key_len != 16 && key_len != 32) {
        LOG(ERROR, _("invalid key length"));
        return false;
    }
    if (iv_len < 7 || iv_len > 13) {
        LOG(ERROR, _("invalid IV length"));
        return false;
    }
    if (tag_len < 4 || tag_len > 16 || tag_len % 2 != 0) {
        LOG(ERROR, _("invalid tag length"));
        return false;
    }
    return true;
}
