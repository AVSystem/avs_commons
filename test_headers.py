#!/usr/bin/env python3
#
# Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import re
import sys

# Verifies that the project is only using plain standard C99 headers.

INCLUDE_WHITELIST = {
    r'assert\.h',
    # r'complex\.h',
    r'ctype\.h',
    r'errno\.h',
    # r'fenv\.h',
    # r'float\.h',
    r'inttypes\.h',
    # r'iso646\.h',
    r'limits\.h',
    # r'locale\.h',
    r'math\.h',
    # r'setjmp\.h',
    # r'signal\.h',
    r'stdarg\.h',
    r'stdbool\.h',
    r'stddef\.h',
    r'stdint\.h',
    r'stdio\.h',
    r'stdlib\.h',
    r'string\.h',
    # r'tgmath\.h',
    # r'time\.h',
    # r'wchar\.h',
    # r'wctype\.h',
    r'avs_commons_init\.h',
    r'avs_commons_poison\.h',
    r'avs_x_log_config\.h',
    r'avsystem/commons/[^.]*\.h'
}

CONDITIONAL_WHITELIST = {
    (r'global', r'signal\.h'),
    (r'global', r'stdatomic\.h'),
    (r'mbedtls', r'mbedtls/.*'),
    (r'openssl', r'libp11.h'),
    (r'openssl', r'openssl/.*'),
    (r'openssl', r'sys/time\.h'),
    (r'tinydtls', r'tinydtls/.*'),
    (r'compression', r'zlib\.h'),
    (r'avs_openssl_common\.h', r'valgrind/.*'),
    (r'avs_strings\.c', r'float\.h')
}

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Error: you must provide absolute path to the file to check')
        sys.exit(1)

    filename = sys.argv[1]

    if any(w in filename for w in ('/test/', '/tests/', '/compat/', '/unit/')):
        sys.exit(0)

    with open(filename, 'r') as fp:
        contents = fp.readlines()

    for line in contents:
        m = re.match(r'^\s*#\s*include\s*<([^>]*)>', line)
        if m and not any(re.match(pattern, m.group(1)) for pattern in INCLUDE_WHITELIST) and not any(
                (re.search(condition, filename) and re.match(pattern, m.group(1))) for condition, pattern in
                CONDITIONAL_WHITELIST):
            raise ValueError('Invalid include: %s\n' % (m.group(0),))
