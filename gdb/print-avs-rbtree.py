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

class PrintAvsRbtreeBase(gdb.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.intptr_type = gdb.lookup_type('unsigned long long')
        self.int_type = gdb.lookup_type('int')
        self.output_format = '%%s 0x%%0%dx = %%s' % (self.intptr_type.sizeof * 2,)

        # TODO
        self.color_offset = -32
        self.parent_offset = -24
        self.left_offset = -16
        self.right_offset = -8

    def _print_tree(self, ptr, path='', depth=0, visited_addrs=set()):
        left_ptr_value = ptr.cast(self.intptr_type) + self.left_offset
        left_ptr = left_ptr_value.cast(ptr.type.pointer()).dereference()

        right_ptr_value = ptr.cast(self.intptr_type) + self.right_offset
        right_ptr = right_ptr_value.cast(ptr.type.pointer()).dereference()

        prefix = ''.join(' |' if x == 'L' else '  ' for x in path)
        if path:
            if path[-1] == 'L':
                prefix += '- '
            elif path[-1] == 'R':
                prefix = prefix[:-1] + "'- "

        print(prefix + self.output_format % (path[-1] if path else ' ', int(ptr), str(ptr.dereference())))

        if int(left_ptr) in visited_addrs or int(right_ptr) in visited_addrs:
            print('circular tree detected, stopping')
            return

        visited_addrs.add(left_ptr)
        visited_addrs.add(right_ptr)
        if int(left_ptr) != 0:
            self._print_tree(left_ptr, path + 'L', depth+1, visited_addrs)
        if int(right_ptr) != 0:
            self._print_tree(right_ptr, path + 'R', depth+1, visited_addrs)


class PrintAvsRbtreeSubtree(PrintAvsRbtreeBase):
    def __init__(self):
        super().__init__('print-avs-rbtree-subtree',
                         gdb.COMMAND_DATA,
                         gdb.COMPLETE_EXPRESSION)

    def invoke(self, argv_str, _from_tty):
        args = gdb.string_to_argv(argv_str)

        if len(args) != 1:
            print('usage: print-avs-rbtree-subtree expr\n'
                  '  expr - an expression that avaluates to a valid AVS_RBTREE_NODE pointer\n')
            return

        expr = args[0]

        val = gdb.parse_and_eval(expr)
        if val is None:
            print('cannot evaluate expression: ' + expr)
            return

        if val == 0:
            print('(null)')
        else:
            self._print_tree(val)

class PrintAvsRbtree(PrintAvsRbtreeBase):
    def __init__(self):
        super().__init__('print-avs-rbtree',
                         gdb.COMMAND_DATA,
                         gdb.COMPLETE_EXPRESSION)

    def invoke(self, argv_str, _from_tty):
        args = gdb.string_to_argv(argv_str)

        if len(args) != 1:
            print('usage: print-avs-rbtree expr\n'
                  '  expr - an expression that avaluates to a valid AVS_RBTREE pointer\n')
            return

        expr = args[0]

        val = gdb.parse_and_eval('*(' + expr + ')')
        if val is None:
            print('cannot evaluate expression: ' + expr)
            return

        if val == 0:
            print('(null)')
        else:
            self._print_tree(val)

class PrintAvsRbtreeNode(PrintAvsRbtreeBase):
    def __init__(self):
        super().__init__('print-avs-rbtree-node',
                         gdb.COMMAND_DATA,
                         gdb.COMPLETE_EXPRESSION)

    def invoke(self, argv_str, _from_tty):
        args = gdb.string_to_argv(argv_str)

        if len(args) not in (1, 2):
            print('usage: print-avs-rbtree expr [with_magic]\n'
                  '  expr - an expression that avaluates to a valid AVS_RBTREE_NODE pointer\n'
                  '  with_magic - if present, "magic" fields are displayed\n')
            return

        expr = args[0]
        with_magic = len(args) > 1

        ptr = gdb.parse_and_eval(expr)
        if ptr is None:
            print('cannot evaluate expression: ' + expr)
            return

        if ptr == 0:
            print('(null)')
        else:
            intptr_ptr = ptr.cast(self.intptr_type)
            if with_magic:
                print((intptr_ptr + self.rb_magic_offset))
                print((intptr_ptr + self.rb_magic_offset).cast(self.int_type.pointer()))
                print('rb magic:   %s' % ((intptr_ptr + self.rb_magic_offset).cast(self.int_type.pointer()).dereference()))
                print('tree magic: %s' % ((intptr_ptr + self.tree_magic_offset).cast(self.int_type.pointer()).dereference()))

            print('color:  %s' % ((intptr_ptr + self.color_offset ).cast(self.int_type.pointer()).dereference()))
            print('parent: 0x%%0%dx' % (self.intptr_type.sizeof * 2) % ((intptr_ptr + self.parent_offset).cast(ptr.type.pointer()).dereference()))
            print('left:   0x%%0%dx' % (self.intptr_type.sizeof * 2) % ((intptr_ptr + self.left_offset  ).cast(ptr.type.pointer()).dereference()))
            print('right:  0x%%0%dx' % (self.intptr_type.sizeof * 2) % ((intptr_ptr + self.right_offset ).cast(ptr.type.pointer()).dereference()))

PrintAvsRbtreeSubtree()
PrintAvsRbtree()
PrintAvsRbtreeNode()
