#!/usr/bin/env python3
import sys
import functools
import struct

nodes = int(sys.argv[1]) if len(sys.argv) > 1 else 1

def binsearch_depth(nums, num):
    if not nums:
        raise ValueError('should never happen')

    at = len(nums) // 2
    if nums[at] == num:
        return 1
    elif num < nums[at]:
        return 1 + binsearch_depth(nums[:at], num)
    else:
        return 1 + binsearch_depth(nums[at+1:], num)

values = list(range(1, nodes+1))
ordered_values = sorted(values, key=functools.partial(binsearch_depth, values))
for num in ordered_values:
    sys.stdout.buffer.write(struct.pack('=BI', 0, num))
