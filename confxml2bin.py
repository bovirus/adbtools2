#! /usr/bin/env python3

import re
import sys
import base64
from Cryptodome.Cipher import AES # requires pycrypto

if len(sys.argv) < 5:
    print(_("Usage: confxml2bin.py  <key4conf> <key4cpe> <conf_xml> <confcpe_xml> <conf_bin>"))
    sys.exit(1)

key4conf     = sys.argv[1]
key4cpe      = sys.argv[2]
conf_xml     = sys.argv[3]
confcpe_xml  = sys.argv[4]
conf_bin     = sys.argv[5]

with open(key4conf, "rb") as f:
    pemconf_data = f.read()

with open(key4cpe, "rb") as f:
    pemcpe_data = f.read()

with open(conf_xml, "rb") as f:
    data_in = f.read()

with open(confcpe_xml, "rb") as f:
    datacpe_in = f.read()

# Going for the popular choice...
IV = b"\x00" * AES.block_size


# ----- encode and base64 cpe data

key = pemcpe_data[0x20:0x30]
cipher = AES.new(key, AES.MODE_CBC, IV)

padding_length = AES.block_size - (len(datacpe_in) % AES.block_size)
if padding_length != AES.block_size:
    padding_byte = padding_length.to_bytes(1, "big")
    datacpe_in += padding_byte * padding_length
datacpe_out = cipher.encrypt(datacpe_in)
datacpe_hex = base64.b64encode(datacpe_out)
datacpe2_hex = re.sub(b"(.{72})", b"\\1\n", datacpe_hex, 0, re.DOTALL)
# ---- ecnode and insert datacpe hex

# #<!-- CPE Data: DVA-5592/DVA-5592 system type    : 963138_VD5920 -->
# #<!-- DATA
# #9V/jO+TpbscUypF/41d3Ej15nwHuUp+c4wBWV4uFWb1Zb/nS6QuDiLUoZeJ2s0mksjXrARR2

# match = re.search(b'<!-- DATA.(.*).-->', data_out, re.DOTALL)

data_in = re.sub(b'<!-- DATA\n(.*)\n-->', b"<!-- DATA\n" + datacpe2_hex + b"\n-->",data_in, 1, re.DOTALL)

#with open("conftst.xml", "wb") as f:
#    f.write(data_in)

key = pemconf_data[0x20:0x30]
cipher = AES.new(key, AES.MODE_CBC, IV)

padding_length = AES.block_size - (len(data_in) % AES.block_size)
if padding_length != AES.block_size:
    padding_byte = padding_length.to_bytes(1, "big")
    data_in += padding_byte * padding_length
data_out = cipher.encrypt(data_in)

with open(conf_bin, "wb") as f:
    f.write(data_out)

