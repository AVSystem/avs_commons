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

# installation: append "source PATH_TO_THIS_SCRIPT" to ~/.gdbinit

import gdb

class PrintAvsList(gdb.Command):
    def __init__(self):
        # python API for gdb < 7.7 does not have COMPLETE_EXPRESSION
        complete = getattr(gdb, 'COMPLETE_EXPRESSION', gdb.COMPLETE_SYMBOL)

        super(PrintAvsList, self).__init__('print-avs-list',
                                           gdb.COMMAND_DATA,
                                           complete)

    def _get_list_ptr_offset(self):
        # It seems that "struct avs_list_space_for_next_helper_struct__" does
        # not exist, and even "avs_max_align_t" sometimes is not available
        # (e.g. in avs_list_test binary).
        #
        # Additionally, GDB does not have any kind of "alignof" command (see
        # https://sourceware.org/bugzilla/show_bug.cgi?id=17095 ) and is not
        # able to parse inline "struct {...}". And one cannot create a new
        # gdb.Type representing such struct, since gdb.Types are read-only.
        #
        # Using sizeof() instead is good enough to work on x86_64. It's the
        # closest we can get.
        maxalign_types = [ 'void*', 'void(*)()', 'long double', 'intmax_t' ]
        return -max(gdb.parse_and_eval('sizeof(%s)' % t) for t in maxalign_types)

    def _get_output_format(self):
        return '0x%%0%dx [%%d] = %%s' % (gdb.lookup_type('void').pointer().sizeof * 2,)

    def _print_list(self, ptr, limit, index=0, visited_addrs=set()):
        """
        Prints up to LIMIT elements of an AVS_LIST given by its PTR.

        Args:
            ptr:           gdb.Value   - an AVS_LIST element pointer.
            limit:         int or None - maximum number of elements to display or None if unlimited
            index:         int         - used internally to assign indices to displayed elements
            visited_addrs: set[int]    - used internally to break printing if a cycle is detected
        """
        if limit is not None and index >= limit:
            return

        print(self._get_output_format() % (int(ptr), index, str(ptr.dereference())))

        next_ptr_value = ptr.cast(gdb.lookup_type('void').pointer()) + self._get_list_ptr_offset()
        next_ptr = next_ptr_value.cast(ptr.type.pointer()).dereference()

        if int(next_ptr) in visited_addrs:
            print('circular list detected, stopping')
            return

        if next_ptr != 0:
            self._print_list(next_ptr, limit, index + 1, visited_addrs | set([int(next_ptr)]))

    def invoke(self, argv_str, _from_tty):
        args = gdb.string_to_argv(argv_str)

        if len(args) not in (1, 2):
            print('usage: print-avs-list expr [limit=10]\n'
                  '  expr - an expression that avaluates to a valid AVS_LIST element pointer\n'
                  '  limit - number of elements to display; a value <= 0 means no limit')
            return

        expr = args[0]

        limit = int(args[1]) if len(args) > 1 else 0
        if limit <= 0:
            limit = None

        val = gdb.parse_and_eval(expr)
        if val is None:
            print('cannot evaluate expression: ' + expr)
            return

        if val == 0:
            print('(empty list)')
        else:
            self._print_list(val, limit)

PrintAvsList()
