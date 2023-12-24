import sys
import urllib.request, urllib.error


# python3 sol_3.2.3.py 3.2.3_ciphertext.hex sol_3.2.3.txt
# curl http://172.22.159.75:4000/mp3/yuankai4/?$(cat 3.2.3_ciphertext.hex)


def get_status(cipher):
    try:
        resp = urllib.request.urlopen("http://172.22.159.75:4000/mp3/yuankai4/?" + cipher)
        print(resp.read())
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print("padding is correct")
            return True
        else:
            print("padding is not correct")
            return False


def strip_padding(msg):
    padlen = 17 - ord(msg[-1])
    return msg[:-padlen]


# Using oracle to decrypt byte by byte
# Following the discussion slides. Try to find out Dec(C3,k)[15] when we expect the oracle return 404, which is P3[15]=\x10.
# Loop through all possible value for C2[15] from 0 to 255 to get the value. Then because Dec(C3,k)[15] = P3[15] xor C2[15].
# We can get P3[15]. Next we do the same thing on the 14th block by letting newC3[15] xor Dec(C3,k)[15] = \x0f.
def decrypt_block(segment):
    current_block_starting_index = segment * 32
    previous_block_starting_index = (segment - 1) * 32
    current_block = raw_cipher_text[current_block_starting_index:current_block_starting_index + 32]
    previous_block = raw_cipher_text[previous_block_starting_index:previous_block_starting_index + 32]
    print(current_block)
    block_plain_text = ""
    decrypted_text = ""  # Intermediate result that is after DEC and before xor.
    for byteIndex in range(15, -1, -1):
        block_to_replace = previous_block[2 * byteIndex:2 * byteIndex + 2]
        print("Replacing byte " + block_to_replace)

        new_rest_of_previous_block = ''
        rest_padding = 15
        for rest_of_previous_index in range(0, len(decrypted_text), 2):
            decrypted_int = int(decrypted_text[rest_of_previous_index:rest_of_previous_index + 2], 16)
            new_rest_of_previous_int = decrypted_int ^ rest_padding
            rest_padding -= 1
            new_rest_of_previous_block += '{:02x}'.format(new_rest_of_previous_int)

        for newValue in range(256):
            # Force the value to be 2 characters.
            # Extract until the current block to make sure padding works
            new_cipher = raw_cipher_text[:previous_block_starting_index + 2 * byteIndex] + '{:02x}'.format(
                newValue) + new_rest_of_previous_block + raw_cipher_text[
                                                         current_block_starting_index:current_block_starting_index + 32]
            print(new_cipher)
            if get_status(new_cipher):
                dec_text = newValue ^ 16
                decrypted_text = '{:02x}'.format(dec_text) + decrypted_text
                result = int(block_to_replace, 16) ^ dec_text
                result_str = chr(result)
                block_plain_text = result_str + block_plain_text
                print("Decrypted result is: " + result_str)
                break

    print(block_plain_text)
    return block_plain_text


url = "http://172.22.159.75:4000/mp3/yuankai4/?"
cipher_file = sys.argv[1]
output_file = sys.argv[2]
f_c = open(cipher_file, 'r')
raw_cipher_text = f_c.read().strip()

segments = len(raw_cipher_text) // 32

plain_text = ""
for i in range(segments - 1, 0, -1):
    plain_text = decrypt_block(i) + plain_text

plain_text_unpad = strip_padding(plain_text)
print(plain_text_unpad)
f_o = open(output_file, 'w')
f_o.write(plain_text_unpad)
