.global your_asm_fn
.section .text

your_asm_fn:

push    %ebp
mov     %esp,%ebp

# Your code here
# set value for variable mp
push $0xc001f00d
# set value for variable sec
push $0xc105ed
# set value for variable app
push $0xacce55ed
call practice

leave
ret
