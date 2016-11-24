python

class PrintAvsList(gdb.Command):
    def __init__(self):
        super().__init__('print-avs-list',
                         gdb.COMMAND_DATA,
                         gdb.COMPLETE_EXPRESSION)

        self.intptr_type = gdb.lookup_type('unsigned long long')
        self.output_format = '0x%%0%dx [%%d] = %%s' % (self.intptr_type.sizeof * 2,)
        # TODO: will AVS_LIST_SPACE_FOR_NEXT__ always be this?
        self.list_ptr_offset = -16

    def _print_list(self, ptr, index=0, visited_addrs=set()):
        print(self.output_format % (int(ptr), index, str(ptr.dereference())))

        next_ptr_value = ptr.cast(self.intptr_type) + self.list_ptr_offset
        next_ptr = next_ptr_value.cast(ptr.type.pointer()).dereference()

        if int(next_ptr) in visited_addrs:
            print('circular list detected, stopping')
            return

        if next_ptr != 0:
            self._print_list(next_ptr, index + 1, visited_addrs | set([int(next_ptr)]))

    def invoke(self, argv_str, _from_tty):
        args = gdb.string_to_argv(argv_str)
        arg = args[0]

        sym, _dunno = gdb.lookup_symbol(arg)
        val = sym.value(gdb.selected_frame())

        if val == 0:
            print('(empty list)')
        else:
            self._print_list(val)

class PrintAvsRbtree(gdb.Command):
    def __init__(self):
        super().__init__('print-avs-rbtree',
                         gdb.COMMAND_DATA,
                         gdb.COMPLETE_EXPRESSION)

        self.intptr_type = gdb.lookup_type('unsigned long long')
        self.output_format = '%%s0x%%0%dx [%%d] = %%s' % (self.intptr_type.sizeof * 2,)

        # TODO
        self.left_offset = -16
        self.right_offset = -8

    def _print_list(self, ptr, index=0, visited_addrs=set()):
        print(self.output_format % (int(ptr), index, str(ptr.dereference())))

        next_ptr_value = ptr.cast(self.intptr_type) + self.list_ptr_offset
        next_ptr = next_ptr_value.cast(ptr.type.pointer()).dereference()

        if int(next_ptr) in visited_addrs:
            print('circular list detected, stopping')
            return

        if next_ptr != 0:
            self._print_list(next_ptr, index + 1, visited_addrs | set([int(next_ptr)]))

    def invoke(self, argv_str, _from_tty):
        args = gdb.string_to_argv(argv_str)
        arg = args[0]

        sym, _dunno = gdb.lookup_symbol(arg)
        val = sym.value(gdb.selected_frame())

        if val == 0:
            print('(empty list)')
        else:
            self._print_list(val)

PrintAvsList()
