#!/usr/bin/env python3
#
# Copyright 2023 AVSystem <avsystem@avsystem.com>
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
import json
import re
import sys

# Verifies that the project is only using plain standard C99 headers.

GLOBAL_WHITELIST = {
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
    # r'wctype\.h'
}

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Error: you must provide absolute path to the file to check')
        sys.exit(1)

    filename = sys.argv[1]

    with open(filename, 'r') as fp:
        contents = fp.readlines()

    conditional_whitelist = {}
    if len(sys.argv) > 2:
        with open(sys.argv[2], 'r') as fp:
            conditional_whitelist = json.load(fp)

    for line in contents:
        valid = False
        m = re.match(r'^\s*#\s*include\s*<([^>]*)>', line)
        if not m:
            valid = True
        elif any(re.match(pattern, m.group(1)) for pattern in GLOBAL_WHITELIST):
            valid = True
        else:
            for condition, whitelist in conditional_whitelist.items():
                if re.search(condition, filename) and any(
                        re.match(pattern, m.group(1)) for pattern in whitelist):
                    valid = True
                    break

        if not valid:
            raise ValueError('Invalid include: %s\n' % (m.group(0),))
