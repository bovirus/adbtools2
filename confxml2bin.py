#! /usr/bin/env python3

import re
import sys
import base64
import os
import gettext
import locale
from Cryptodome.Cipher import AES # requires pycrypto

mydir    = sys.path[0]              # not correct on exe file from pyinstaller
mydir    = os.path.dirname(os.path.realpath(__file__))

def language_set(lan):
    global _
    if (os.path.isdir(mydir + '/locale/' + lan)):
        slan = gettext.translation('adbtools2', localedir='locale', languages=[lan])
        slan.install()
    else:
        _ = lambda s: s

def language_default():
    lan = 'EN'
    try:
        if sys.argv[1] == '-l':
            lan = sys.argv[2]
            del sys.argv[1:3]
    except:
        (lancode, lanenc) = locale.getdefaultlocale()
        lancode2=lancode[0:2]
        if (os.path.isdir(mydir + '/locale/' + lancode)):
            lan = lancode
        if (os.path.isdir(mydir + '/locale/' + lancode2)):
            lan = lancode2
        else:
            lan = 'en'
    return lan

lan = language_default()
language_set(lan)

if len(sys.argv) < 5:
    print(_("Usage: confxml2bin.py  [ -l it|en ] <key4conf> <key4cpe> <conf_xml> <confcpe_xml> <conf_bin>"))
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

