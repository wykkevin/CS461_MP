import sys
from pymd5 import md5, padding
import urllib.parse

# python3 sol_3.2.1.py 3.2.1_query.txt 3.2.1_command3.txt sol_3.2.1.txt
query_file = sys.argv[1]
command_file = sys.argv[2]
output_file = sys.argv[3]
f_q = open(query_file, 'r')
f_c = open(command_file, 'r')
query = f_q.read().strip()
command = f_c.read().strip()

first_equal_index = query.find('=')
first_and_index = query.find('&')

token_string = query[first_equal_index + 1:first_and_index]
user_string = query[first_and_index + 1:]

h = md5(state=token_string, count=512)
h.update(command)
new_token = h.hexdigest()

full_command = "token=" + new_token + "&" + user_string + urllib.parse.quote((padding((len(user_string) + 8) * 8))) + command
print(full_command)
f_o = open(output_file, 'w')
f_o.write(full_command)
