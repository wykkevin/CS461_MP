import sys
import math
import pbp
from Crypto.PublicKey import RSA
import Crypto


# python3 sol_3.2.4.py 3.2.4_ciphertext.enc.asc moduli.hex sol_3.2.4.txt

# Used some code snippets from https://facthacks.cr.yp.to/, which is also created by some authors in the given paper,
# to calculate batch gcd.
def prod(list_of_numbers):
    output = 1
    for number in list_of_numbers:
        output *= number
    return output


def producttree(X):
    result = [X]
    while len(X) > 1:
        X = [prod(X[i * 2:(i + 1) * 2]) for i in range((len(X) + 1) // 2)]
        result.append(X)
    return result


def gcd(x, y):
    while x != 0: x, y = y % x, x
    return abs(y)


def batchgcd_faster(X):
    prods = producttree(X)
    R = prods.pop()
    while prods:
        X = prods.pop()
        R = [R[math.floor(i / 2)] % X[i] ** 2 for i in range(len(X))]
    return [gcd(r // n, n) for r, n in zip(R, X)]


cipher_file = sys.argv[1]
moduli_file = sys.argv[2]
output_file = sys.argv[3]
f_c = open(cipher_file, 'r')
f_m = open(moduli_file, 'r')
cipher_text = f_c.read()
moduli_text = f_m.read().strip()
modulis = moduli_text.split("\n")
moduli_int_list = []

for moduli in modulis:
    moduli_int_list.append(int(moduli, 16))

batchedgcd_results = batchgcd_faster(moduli_int_list)

e = 65537
for i in range(len(batchedgcd_results)):
    p = int(batchedgcd_results[i])
    n = int(moduli_int_list[i])
    q = n // p
    if p == 1 or q == 1:
        print("ignore")
    else:
        d = Crypto.Util.number.inverse(e, (p-1)*(q-1))
        # Construct the RSA key for the computed values. Try to decrypt the ciphertext with the built key.
        try:
            rsakey = RSA.construct((int(n), int(e), int(d)))
            plaintext = pbp.decrypt(rsakey, cipher_text)
            print(plaintext)
            f_o = open(output_file, 'w')
            f_o.write(plaintext.decode())
            break
        except ValueError as err:
            # The PBP decrypt function will throw a value error for an incorrect RSA key pass
            print(err)