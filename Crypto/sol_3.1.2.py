import sys

# python3 sol_3.1.2.py 3.1.2_sub_ciphertext.txt 3.1.2_sub_key.txt sol_3.1.2.txt 
ciphertext_file = sys.argv[1]
key_file = sys.argv[2]
output_file = sys.argv[3]
f_c = open(ciphertext_file,'r')
f_k = open(key_file,'r')
cipher = f_c.read().strip()
key = f_k.read().strip()

key_map = {}
for i in range(26):
	key_map[key[i:i+1]] = chr(65+i)

output = ""
for j in range(len(cipher)):
	cipher_char = cipher[j:j+1]
	plain_char = key_map.get(cipher_char)
	if plain_char is None:
		output += cipher_char
	else:
		output += plain_char
f_o = open(output_file,'w')
f_o.write(output)
