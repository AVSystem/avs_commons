/*
 * Copyright 2025 AVSystem <avsystem@avsystem.com>
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

#include <avs_commons_init.h>

#ifdef AVS_COMMONS_WITH_AVS_STREAM

#    include <avsystem/commons/avs_stream.h>

#    define MODULE_NAME avs_stream
#    include <avs_x_log_config.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

avs_error_t _avs_stream_empty_finish_message(avs_stream_t *stream);

VISIBILITY_PRIVATE_HEADER_END

#endif // AVS_COMMONS_WITH_AVS_STREAM
