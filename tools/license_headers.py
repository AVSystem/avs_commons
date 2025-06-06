#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2025 AVSystem <avsystem@avsystem.com>
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

import os
import re
import subprocess
import sys
from argparse import ArgumentParser
from io import StringIO

import avs_common

EXPECTED_COPYRIGHT_HEADER = 'Copyright 2025 AVSystem <avsystem@avsystem.com>'

LICENSE = (
    '',
    'Licensed under the Apache License, Version 2.0 (the "License");',
    'you may not use this file except in compliance with the License.',
    'You may obtain a copy of the License at',
    '',
    '    http://www.apache.org/licenses/LICENSE-2.0',
    '',
    'Unless required by applicable law or agreed to in writing, software',
    'distributed under the License is distributed on an "AS IS" BASIS,',
    'WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.',
    'See the License for the specific language governing permissions and',
    'limitations under the License.'
)

IGNORE_PATTERNS = list(map(re.compile, [
    '/fuzz/input/',
    'README',
    '^CHANGELOG\.md$',
    '^LICENSE$',
    '^NOTICE$',
    '^\.git',
    '^avs_commons_test\.lsan\.supp$',
    '^avs_commons_test\.valgrind\.supp$',
    '^conditional_headers_whitelist\.json$',
    '^doc/Doxyfile\.in$',
    '__pycache__',
]))

SUBMODULES = []


def show_license():
    print(EXPECTED_COPYRIGHT_HEADER)
    for line in LICENSE:
        print(line)


def show_ignores():
    for pattern in IGNORE_PATTERNS:
        print(pattern.pattern)


def is_ignored(filename):
    for pattern in IGNORE_PATTERNS:
        if pattern.search(filename) is not None:
            return True
    return False


def get_file_list(repo='.'):
    output = subprocess.run(['git', 'diff', '--name-only',
                             # semi-well known SHA for git's empty tree
                             # see http://stackoverflow.com/q/9765453 for details
                             # might also use `git hash-object -t tree /dev/null`
                             '4b825dc642cb6eb9a060e54bf8d69288fbee4904'],
                            stdout=subprocess.PIPE, cwd=repo, universal_newlines=True, check=True)
    with StringIO(output.stdout) as f:
        return [os.path.normpath(os.path.join(repo, line.strip())) for line in f]


def check_license(filename):
    prefix = None
    expected_line = 0

    with open(filename, mode='r', encoding='utf-8', errors='surrogateescape') as f:
        for line in f:
            trimmed = line.strip()
            if prefix is None:
                found = trimmed.split(EXPECTED_COPYRIGHT_HEADER)
                if len(found) > 1:
                    prefix = found[0]
            elif trimmed == (prefix + LICENSE[expected_line]).strip():
                expected_line += 1
                if expected_line == len(LICENSE):
                    return True
            else:
                break
    return False


def _check_submodule(submodule, root='.'):
    '''
    Runs the license check for the given submodule.

    :param submodule: The relative path to the considered submodule.

    :param root: The main repo dir.
    '''

    submodule_path = os.path.join(root, submodule)
    script_path = os.path.join(submodule_path, 'tools/license_headers.py')

    if not os.path.exists(script_path):
        print('Submodule %s has no license check script on path %s' %
              (submodule, script_path))
        return

    subprocess.run([script_path, '-r', submodule_path], check=True)


def _main():
    parser = ArgumentParser(description='Check which files in the project do not have '
                                        'the proper license header.')
    parser.add_argument('-l', '--show-license',
                        help='Displays the expected license header.',
                        action='store_true')
    parser.add_argument('-i', '--show-ignores',
                        help='Displays the currently hard-coded patterns for ignored '
                             'file names.',
                        action='store_true')
    parser.add_argument('-n', '--no-ignores',
                        help='Checks even files that are normally ignored.',
                        action='store_true')
    parser.add_argument('-r', '--root',
                        help='Project root directory. Must be a git working tree.',
                        default='.')

    args = parser.parse_args()

    if args.show_license:
        show_license(args.commercial)
        return 0

    if args.show_ignores:
        show_ignores()
        return 0

    result = 0
    os.chdir(args.root)
    file_list = get_file_list()
    for f in file_list:
        if (os.path.isfile(f)
                and not os.path.islink(f)
                and (args.no_ignores or not is_ignored(f))
                and not check_license(f)):
            print(f)
            result = 1

    for submodule in SUBMODULES:
        try:
            _check_submodule(submodule)
        except Exception:
            result = 1

    return result


if __name__ == '__main__':
    sys.exit(_main())
