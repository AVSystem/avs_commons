#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

import argparse
import os
import re
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def read_full_file(filename):
    with open(filename) as f:
        return f.read()


def is_purely_preprocessor_header(content):
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.MULTILINE | re.DOTALL)
    content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
    for line in content.split('\n'):
        trimmed = line.strip()
        if trimmed != '' and not trimmed.startswith('#'):
            return False
    return True


def has_proper_extern_c_clause(filename):
    content = read_full_file(filename)
    return ('extern "C"' in content) or is_purely_preprocessor_header(content)


def _main():
    parser = argparse.ArgumentParser(
        description='Check if all public headers contain an extern "C" clause')
    parser.add_argument('-p', '--path', help='Project root path to start checking in',
                        default=PROJECT_ROOT)
    parser.add_argument('-r', '--regex',
                        help='Regular expression that matches all files that need to be checked',
                        default=r'/include_public/.*\.h$')
    args = parser.parse_args()

    regex = re.compile(args.regex)

    failure = False

    for root, dirs, files in os.walk(args.path):
        if '.git' in files:
            # ".git" file that is not a subdirectory means that most likely
            # we're in a submodule directory - do not iterate further
            dirs.clear()
            continue
        try:
            dirs.remove('.git')
        except ValueError:
            pass

        for filename in files:
            full_filename = os.path.join(root, filename)
            if regex.search(full_filename) is not None:
                if not has_proper_extern_c_clause(full_filename):
                    failure = True
                    sys.stderr.write('Missing extern "C" conditional in %s\n' % (full_filename,))

    if failure:
        return 1


if __name__ == '__main__':
    sys.exit(_main())
