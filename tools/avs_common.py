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

import shutil
import tempfile
import os

COMMERCIAL_FILE_LIST_NAME = '.avsystem_commercial'


def each_source_file(project_dir, ignore_pred=lambda _: False):
    '''
    Yields the files contained in the given directory.

    :param project_dir: Project directory.
    :param ignore_pred: Predicate to check if the given file should be excluded.
    '''

    for root, dirs, files in os.walk(project_dir):
        try:
            dirs.remove('.git')
        except ValueError:
            pass
        for filename in files:
            full_filename = os.path.join(root, filename)
            if ignore_pred(full_filename):
                continue
            if os.path.isfile(full_filename) and not os.path.islink(full_filename):
                yield full_filename


def each_source_file_streams(project_dir, ignore_pred=lambda _: False):
    '''
    For each file contained in the given directory yields a pair containing
    a path to a given file with a path to its temporary file. When it yields
    the next time, it copies the content of the temporary file to the original
    one.

    :param project_dir: Project directory.
    :param ignore_pred: Predicate to check if the given file should be excluded.
    '''

    for full_filename in each_source_file(project_dir, ignore_pred):
        with tempfile.NamedTemporaryFile() as out:
            with open(full_filename, 'rb') as input:
                yield out, input
            out.flush()
            shutil.copyfile(out.name, full_filename)

