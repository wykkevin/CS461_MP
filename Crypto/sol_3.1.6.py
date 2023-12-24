import sys

# python3 sol_3.1.6.py 3.1.6_input_string.txt 3.1.6_output.hex
input_file = sys.argv[1]
output_file = sys.argv[2]
f_i = open(input_file,'r')
input_text = f_i.read().strip()
input_byte = input_text.encode()
mask = 0x3FFFFFFF
outHash = 0x0
for byte in input_byte:
	intermediate_value = ((byte ^ 0xCC) << 24) | ((byte ^ 0x33) << 16) | ((byte ^ 0xAA) << 8) | (byte ^ 0x55)
	outHash = (outHash & mask) + (intermediate_value & mask)
f_o = open(output_file,'w')
f_o.write(hex(outHash))