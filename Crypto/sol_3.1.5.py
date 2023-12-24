import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# python3 sol_3.1.5.py 3.1.5_RSA_ciphertext.hex 3.1.5_RSA_private_key.hex 3.1.5_RSA_modulo.hex sol_3.1.5.hex
ciphertext_file = sys.argv[1]
key_file = sys.argv[2]
modulo_file = sys.argv[3]
output_file = sys.argv[4]
f_c = open(ciphertext_file,'r')
f_k = open(key_file,'r')
f_m = open(modulo_file,'r')
cipher_text = f_c.read().strip()
key = f_k.read().strip()
modulo = f_m.read().strip()

cipher_text_dec = int(cipher_text,16)
key_dec = int(key,16)
modulo_dec = int(modulo,16)
plain_text = pow(cipher_text_dec, key_dec, modulo_dec)
plain_text_hex = hex(plain_text)[2:]
f_o = open(output_file,'w')
f_o.write(plain_text_hex)