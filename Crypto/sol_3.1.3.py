import sys
from Crypto.Cipher import AES

# python3 sol_3.1.3.py 3.1.3_aes_ciphertext.hex 3.1.3_aes_key.hex 3.1.3_aes_iv.hex sol_3.1.3.txt
ciphertext_file = sys.argv[1]
key_file = sys.argv[2]
iv_file = sys.argv[3]
output_file = sys.argv[4]
f_c = open(ciphertext_file,'r')
f_k = open(key_file,'r')
f_i = open(iv_file,'r')
cipher_text = f_c.read().strip()
key = f_k.read().strip()
iv = f_i.read().strip()
new_key = bytes.fromhex(key)
new_iv = bytes.fromhex(iv)
new_cipher_text = bytes.fromhex(cipher_text)

cipher = AES.new(new_key, AES.MODE_CBC, new_iv)
plain_text = cipher.decrypt(new_cipher_text)
f_o = open(output_file,'wb')
f_o.write(plain_text)