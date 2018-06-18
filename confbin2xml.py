#! /usr/bin/env python3

import re
import sys
import base64
from Cryptodome.Cipher import AES # requires pycrypto

if len(sys.argv) < 5:
    print("Usage: confbin2xml.py  <key4conf> <key4cpe> <conf_bin> <conf_xml> <confcpe_xml>")
    exit(1)

key4conf     = sys.argv[1]
key4cpe      = sys.argv[2]
conf_bin     = sys.argv[3]
conf_xml     = sys.argv[4]
confcpe_xml  = sys.argv[5]

#key_filename = sys.argv[2]
#in_filename = sys.argv[3]
#out_filename = sys.argv[4]

with open(key4conf, "rb") as f:
    pemconf_data = f.read()

with open(key4cpe, "rb") as f:
    pemcpe_data = f.read()

with open(conf_bin, "rb") as f:
    data_in = f.read()

# Going for the popular choice...
IV = b"\x00" * AES.block_size

# Just take a random chunk out of the file and use it as our key
key = pemconf_data[0x20:0x30]
cipher = AES.new(key, AES.MODE_CBC, IV)

#if task == "sym_encrypt":
#    padding_length = AES.block_size - (len(data_in) % AES.block_size)
#    if padding_length != AES.block_size:
#        padding_byte = padding_length.to_bytes(1, "big")
#        data_in += padding_byte * padding_length
#    data_out = cipher.encrypt(data_in)
#elif task == "sym_decrypt":

data_out = cipher.decrypt(data_in)
# Padding is a badly implemented PKCS#7 where 16 bytes padding is ignored,
# so we have to check all previous bytes to see if it is valid.
padding_length = data_out[-1]
if (padding_length < AES.block_size) & (padding_length < len(data_out)):
    for i in range(0, padding_length):
        if data_out[-1 - i] != padding_length:
            break
    else:
        data_out = data_out[:-padding_length]
#else:
#    raise NotImplementedError("Operation not supported")



with open(conf_xml, "wb") as f:
    f.write(data_out)

#<!-- CPE Data: DVA-5592/DVA-5592 system type    : 963138_VD5920 -->
#<!-- DATA
#9V/jO+TpbscUypF/41d3Ej15nwHuUp+c4wBWV4uFWb1Zb/nS6QuDiLUoZeJ2s0mksjXrARR2

match = re.search(b'<!-- DATA.(.*).-->', data_out, re.DOTALL)

if match:
    cpedata_hex = match.group(1)
    with open(confcpe_xml, "wb") as f:
        f.write(cpedata_hex)
else:
    print ("No DATA match\n")
    exit(1)
    
cpedata_bin = base64.b64decode(cpedata_hex)

#with open("cpe.bin", "wb") as f:
#    f.write(cpedata_bin)

#-----
key = pemcpe_data[0x20:0x30]
cipher = AES.new(key, AES.MODE_CBC, IV)    
cpedata_out = cipher.decrypt(cpedata_bin)
# Padding is a badly implemented PKCS#7 where 16 bytes padding is ignored,
# so we have to check all previous bytes to see if it is valid.
padding_length = cpedata_out[-1]
if (padding_length < AES.block_size) & (padding_length < len(cpedata_out)):
    for i in range(0, padding_length):
        if cpedata_out[-1 - i] != padding_length:
            break
    else:
        cpedata_out = cpedata_out[:-padding_length]

with open(confcpe_xml, "wb") as f:
    f.write(cpedata_out)

