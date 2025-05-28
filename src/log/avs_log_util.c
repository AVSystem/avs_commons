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

#define MODULE_NAME avs_log
#include <avs_commons_init.h>
#include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

#ifdef AVS_COMMONS_WITH_INTERNAL_LOGS
void _avs_log_oom__(void) {
    LOG(ERROR, _("out of memory"));
}
#endif // AVS_COMMONS_WITH_INTERNAL_LOGS
