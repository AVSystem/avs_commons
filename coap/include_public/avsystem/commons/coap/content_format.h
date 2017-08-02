/*
 * Copyright 2017 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COAP_CONTENT_FORMAT_H
#define AVS_COAP_CONTENT_FORMAT_H

/** Auxiliary constants for common Content-Format Option values */

#define AVS_COAP_FORMAT_APPLICATION_LINK 40

#define AVS_COAP_FORMAT_PLAINTEXT 0
#define AVS_COAP_FORMAT_OPAQUE 42
#define AVS_COAP_FORMAT_TLV 11542
#define AVS_COAP_FORMAT_JSON 11543

#define AVS_COAP_FORMAT_LEGACY_PLAINTEXT 1541
#define AVS_COAP_FORMAT_LEGACY_TLV 1542
#define AVS_COAP_FORMAT_LEGACY_JSON 1543
#define AVS_COAP_FORMAT_LEGACY_OPAQUE 1544

/**
 * A magic value used to indicate the absence of the Content-Format option.
 * Mainly used during CoAP message parsing, passing it to the info object does
 * nothing.
 * */
#define AVS_COAP_FORMAT_NONE 65535

#endif // AVS_COAP_CONTENT_FORMAT_H
