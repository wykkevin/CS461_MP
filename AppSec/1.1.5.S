# Use https://stackoverflow.com/questions/9342410/sys-execve-system-call-from-assembly to know that I can use "asciz" 
.section .data
filename:
.asciz       "/bin/sh"

.global _main
.section .text

_main:

push    %ebp
mov     %esp,%ebp

# Your code here
mov $11, %eax
mov $filename, %ebx
push $0x00
push %ebx
mov %esp, %ecx
mov $0x00, %edx
int  $0x80  

leave
ret
