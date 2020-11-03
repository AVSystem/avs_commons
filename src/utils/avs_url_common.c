/*
 * Copyright 2020 AVSystem <avsystem@avsystem.com>
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

/*
 * Functions excluded from avs_url.c in "net" because they are used also
 * in the other modules.
 *
 * In the future the whole avs_url.c should be moved to the separate module
 */

#include <avs_commons_init.h>

#ifdef AVS_COMMONS_WITH_AVS_UTILS

#    include <assert.h>
#    include <ctype.h>
#    include <stdlib.h>
#    include <string.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_url.h>
#    include <avsystem/commons/avs_utils.h>

#    define MODULE_NAME avs_utils
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

#    define URL_PTR_INVALID SIZE_MAX

int avs_url_percent_decode(char *data, size_t *unescaped_length) {
    char *src = data, *dst = data;

    if (!strchr(data, '%')) {
        /* nothing to unescape */
        *unescaped_length = strlen(data);
        return 0;
    }

    while (*src) {
        if (*src == '%') {
            if (isxdigit((unsigned char) src[1])
                    && isxdigit((unsigned char) src[2])) {
                char ascii[3];
                ascii[0] = src[1];
                ascii[1] = src[2];
                ascii[2] = '\0';
                *dst = (char) strtoul(ascii, NULL, 16);
                src += 3;
                dst += 1;
            } else {
                LOG(ERROR, _("bad escape format (%%XX) "));
                return -1;
            }
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';

    *unescaped_length = (size_t) (dst - data);
    return 0;
}

#endif // AVS_COMMONS_WITH_AVS_UTILS
