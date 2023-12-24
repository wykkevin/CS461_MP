import hashlib
import re
import string
import random
import time

any_spaces_tabs = "([ \t]+)*"
any_number = "[1-9]"
anything = ".*"
any_or_operator = "((or)|(OR)|([|][|]))"
pattern = re.compile(f"{anything}'{any_spaces_tabs}{any_or_operator}{any_spaces_tabs}'{any_number}{anything}".encode())

cnt = 0
start = time.time()
while True:
    password = ''.join(random.choices(string.digits, k=36))
    md5_bytes = hashlib.md5(password.encode()).digest()
    cnt += 1
    if re.match(pattern, md5_bytes):
        end = time.time()
        print(f"Cracked after {cnt} attempts in {round(end-start, 2)} seconds...")
        print(password)
        break

# password=b"575436223053399858457017340705521582"
# print(hashlib.md5(password).digest())
# b"\xea\xc0\xc6\xf3'||'7C\x8d\xb7\x93\xe9\x11\xdc"
