#!/usr/bin/env python3
# -*- coding: latin-1 -*-
blob = """     ���C�
�6�?wף��Iw�@D6|�
v������^d�v����&wm��u3�J���D�60�و�h�O�����.��.n������FU��M�,u���($�k�b���THmnq�"""
from hashlib import sha256
if blob.encode().endswith(b"\xadnq\x7f\xc3\xae"):
	print("I come in peace.")
else:
	print("Prepare to be destroyed!")