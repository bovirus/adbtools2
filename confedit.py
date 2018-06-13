#!/usr/bin/env python3
#
import tempfile
import string
import random
import re
import sys
import base64
import os.path
import io

from pathlib import Path
from tkinter import *
from tkinter import ttk
from tkinter.filedialog import askopenfilename, asksaveasfilename
from Crypto.Cipher import AES # requires pycrypto
from lxml import etree as ET
from io import StringIO

#------------------------------------------------------------------------------
# Some variable meanings:
#   data_in     encrypted configuration binary file in this binary string
#   data_out    decrypted configuration file: xml binary string
#   cpedata_bin encrypted cpe configuration in binary string
#   cpedata_hex encrypted cpe configuration in base64 encoded binary string
#   cpedata_out decrypted cpe configuration file: xml binary string
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# global variables pointing to default file names
#------------------------------------------------------------------------------
mydir    = sys.path[0]
down_pem = mydir + '/download.pem'
up_pem   = mydir + '/upload.pem'

randomstr  = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4))
tmpradix   = tempfile.gettempdir() + '/' + randomstr + '-'
tmpconf    = tmpradix + 'conf.xml'
tmpconfcpe = tmpradix + 'confcpe.xml'

homedir    = str(Path.home())
defaultdir = homedir
loaded_bin = 0                   # binary config loaded
loaded_xml = 0                   # xml config loaded
loaded_cpe = 0                   # cpe xml config loaded

print("mydir:      ",mydir)
print("down_pem:   ",down_pem)
print("up_pem:     ",up_pem)
print("tmpradix:   ",tmpradix)
print("tmpconf:    ",tmpconf)
print("tmpconfcpe: ",tmpconfcpe)
print("homedir:    ",homedir)

load_pems_done = 0

#------------------------------------------------------------------------------
# get_passwords return a string text file with passwords xml string
#     input    xml_str   binary string, xml or cpe xml conf file
#     rturn    text string 
#------------------------------------------------------------------------------
def get_passwords (xml_str):
    xmltree = ET.parse(io.BytesIO(xml_str))
    xmlroot = xmltree.getroot()

    sout = '';
    
    for s in  [ 'AuthPassword', 'Password' ]:
        for i in xmlroot.findall(".//" + s):
            parent  = i.getparent()
            granpa  = parent.getparent()
            try: granpa2s = granpa.getparent().tag
            except: granpa2s=''
            if ((granpa2s != 'X_ADB_MobileModem') and i.text is not None):
                #print(granpa2s + '/' + granpa.tag + '/' + parent.tag)
                sout = sout + granpa2s + '/' + granpa.tag + '/' + parent.tag + "\n"
                for child in parent:
                    if (child.tag in ['Name', 'AuthUserName', 'Password', 'AuthPassword', 'Username',
                                      'Enable', 'Url', 'Alias', 'Hostname' ]):
                        sout = sout + "  " + child.tag + "  " + child.text + "\n"

                sout = sout + "\n"
    return sout

#------------------------------------------------------------------------------
# check_enable_menu - check and, if needed, enable menut items 
#------------------------------------------------------------------------------
def check_enable_menu ():
    global loaded_bin
    global loaded_xml
    global loaded_cpe
    global filem
    global menubar

    if ((loaded_bin > 0 ) or ((loaded_xml + loaded_cpe) > 1)):
        filem.entryconfig(4, state = NORMAL)
        filem.entryconfig(5, state = NORMAL)
        filem.entryconfig(6, state = NORMAL)
        print("enabling menu")
    else:
        filem.entryconfig(4, state = DISABLED)
        filem.entryconfig(5, state = DISABLED)
        filem.entryconfig(6, state = DISABLED)
        print("disabling menu")
        

    print("check_enable_menu - done")

#------------------------------------------------------------------------------
# load_pems - load pem files
#------------------------------------------------------------------------------
def load_pems():
    global pemconf_data, pemcpe_data
    try:
        with open(down_pem, "rb") as f:
            pemconf_data = f.read()
    except:
        print("Error opening: ",down_pem)
        exit(1)

    try:
        with open(up_pem, "rb") as f:
            pemcpe_data = f.read()
    except:
        print("Error opening: ",up_pem)
        exit(1)
        
    load_pems_done = 1
    print("load pems done")
    print("len 1: ", len(pemconf_data))
    print("len 2: ", len(pemcpe_data))
    
    
#------------------------------------------------------------------------------
# load_config - load binary router configuration file - ok
#------------------------------------------------------------------------------
def load_config(*args):
    global data_out
    global cpedata_out
    global defaultdir
    global loaded_bin
    global pemcpe_data
    global pem_data
    name = askopenfilename(initialdir=defaultdir,
                           filetypes =(("Configuration file", "*.bin"),("All Files","*.*")),
                           title = "Choose a file."
                           )
    print (name)
    #Using try in case user types in unknown file or closes without choosing a file.
    try:
        with open(name,'rb') as f:
            data_in = f.read()
    except:
        print("Error opening: ",name)
        exit(1)

    defaultdir=os.path.dirname(name)
    print("defaultdir: ",defaultdir)
    if (not load_pems_done):
        load_pems()

    print("len data_in: ",len(data_in))
    # decrypt config

    # Going for the popular choice...
    IV = b"\x00" * AES.block_size

    # Just take a random chunk out of the file and use it as our key
    key = pemconf_data[0x20:0x30]
    cipher = AES.new(key, AES.MODE_CBC, IV)
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

                
    #-------------------------------------------------------------------------
    # extract the cpe xml data
    #-------------------------------------------------------------------------

    #<!-- CPE Data: DVA-5592/DVA-5592 system type    : 963138_VD5920 -->
    #<!-- DATA
    #9V/jO+TpbscUypF/41d3Ej15nwHuUp+c4wBWV4uFWb1Zb/nS6QuDiLUoZeJ2s0mksjXrARR2

    #with open ("dbg.xml",'wb') as fd:
    #    fd.write(data_out)
    
    match = re.search(b'<!-- DATA.(.*).-->', data_out, re.DOTALL)

    if match:
        cpedata_hex = match.group(1)
    else:
        print ("Error in finding hex data\n")
        exit(1)
    
    cpedata_bin = base64.b64decode(cpedata_hex)
    
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
    print("load_config legth cpedata_out", len(cpedata_out))
    loaded_bin = 1
    check_enable_menu()
    print("---- passwords from data_out ----")
    print(get_passwords(data_out))
    print("---- passwords from cpedata_out ----")
    print(get_passwords(cpedata_out))
    
#------------------------------------------------------------------------------
# load_xmlconfig - load xml router configuration file - ok
#------------------------------------------------------------------------------
def load_xmlconfig(*args):
    global defaultdir
    global loaded_xml
    global data_out
    global defaultdir
    name = askopenfilename(initialdir=defaultdir,
                           filetypes =(("Configuration file", "*.xml"),("All Files","*.*")),
                           title = "Choose a file."
                           )
    print (name)
    #Using try in case user types in unknown file or closes without choosing a file.
    try:
        with open(name,'rb') as f:
            data_out = f.read()
    except:
        print("Error opening: ",name)
        exit(1)

    defaultdir=os.path.dirname(name)
    loaded_xml = 1
    check_enable_menu()
    if (not load_pems_done):
        load_pems()

    
#------------------------------------------------------------------------------
# load_cpexmlconfig - load cpe xml router configuration file - ok 
#------------------------------------------------------------------------------
def load_cpexmlconfig(*args):
    global defaultdir
    global cpedata_out
    global loaded_cpe
    name = askopenfilename(initialdir=defaultdir,
                           filetypes =(("CPE Configuration file", "*.xml"),("All Files","*.*")),
                           title = "Choose a file."
                           )
    print (name)
    #Using try in case user types in unknown file or closes without choosing a file.
    try:
        with open(name,'rb') as f:
            cpedata_out = f.read()
    except:
        print("Error opening ", name)
        exit(1)

    defaultdir=os.path.dirname(name)
    loaded_cpe = 1
    check_enable_menu()
    if (not load_pems_done):
        load_pems()
                                    
#------------------------------------------------------------------------------
# save_config - save router binary configuration file - ok
#------------------------------------------------------------------------------
def save_config(*args):
    global defaultdir
    global data_out
    global cpedata_out
    global pemcpe_data
    global pemconf_data

    if (not load_pems_done):
        load_pems()

    # -------------------------------------------------------------------------
    # encode and base 64 cpe data
    # -------------------------------------------------------------------------
    # Going for the popular choice...
    IV = b"\x00" * AES.block_size

    key = pemcpe_data[0x20:0x30]
    cipher = AES.new(key, AES.MODE_CBC, IV)

    padding_length = AES.block_size - (len(cpedata_out) % AES.block_size)
    if padding_length != AES.block_size:
        padding_byte = padding_length.to_bytes(1, "big")
        cpedata_out += padding_byte * padding_length
        
    cpedata_in  = cipher.encrypt(cpedata_out)
    cpedata_hex = base64.b64encode(cpedata_in)
    cpedata2_hex = re.sub(b"(.{72})", b"\\1\n", cpedata_hex, 0, re.DOTALL)
    #print(cpedata2_hex)

    # -------------------------------------------------------------------------
    # insert data cpe in hex format inside the main xml data and encrypt all
    # -------------------------------------------------------------------------

    # #<!-- CPE Data: DVA-5592/DVA-5592 system type    : 963138_VD5920 -->
    # #<!-- DATA
    # #9V/jO+TpbscUypF/41d3Ej15nwHuUp+c4wBWV4uFWb1Zb/nS6QuDiLUoZeJ2s0mksjXrARR2


    data_out = re.sub(b'<!-- DATA\n(.*)\n-->', b"<!-- DATA\n" + cpedata2_hex + b"\n-->",data_out, 1, re.DOTALL)

    key = pemconf_data[0x20:0x30]
    cipher = AES.new(key, AES.MODE_CBC, IV)

    padding_length = AES.block_size - (len(data_out) % AES.block_size)
    if padding_length != AES.block_size:
        padding_byte = padding_length.to_bytes(1, "big")
        data_out += padding_byte * padding_length
        
    data_in = cipher.encrypt(data_out)

    # -------------------------------------------------------------------------
    # write binary file
    # -------------------------------------------------------------------------
    
    name = asksaveasfilename(initialdir=defaultdir,
                             filetypes =(("Configuration file", "*.bin"),("All Files","*.*")),
                             title = "Choose a file."
                             )
    print (name)
    #Using try in case user types in unknown file or closes without choosing a file.
    try:
        with open(name,'wb') as f:
            f.write(data_in)
    except:
        print("Error writing: ",name)
        exit(1)

    defaultdir=os.path.dirname(name)

#------------------------------------------------------------------------------
# save_xmlconfig - save router xml configuration file - ok
#------------------------------------------------------------------------------
def save_xmlconfig(*args):
    global defaultdir
    name = asksaveasfilename(initialdir=defaultdir,
                             filetypes =(("Save xml configuration file", "*.xml"),("All Files","*.*")),
                             title = "Choose a file."
                             )
    print ("save_xmlconfig file name",name)
    #Using try in case user types in unknown file or closes without choosing a file.
    try:
        with open(name,'wb') as f:
            f.write(data_out)
    except:
        print("Error writing: ",name)
        exit(1)

    defaultdir=os.path.dirname(name)

#------------------------------------------------------------------------------
# save_cpexmlconfig - save router configuration file - ok
#------------------------------------------------------------------------------
def save_cpexmlconfig(*args):
    global defaultdir
    global cpedata_out
    name = asksaveasfilename(initialdir=defaultdir,
                             filetypes =(("Save CPE xml configuration file", "*.xml"),("All Files","*.*")),
                             title = "Choose a file."
                             )
    print ("save_cpexmlconfig file name", name)
    print ("length cpedata_out", len(cpedata_out))
    #Using try in case user types in unknown file or closes without choosing a file.
    try:
        with open(name,'wb') as f:
            f.write(cpedata_out)
    except:
        print("Error writing: ",name)

    defaultdir=os.path.dirname(name)

                                
#------------------------------------------------------------------------------
# confquit - quit the program
#------------------------------------------------------------------------------
def confquit(*args):
    print("Conf quit")
    exit()


root = Tk()
root.title("ADB Configuration Editor")

# menu bar
menubar = Menu(root)
root.config(menu=menubar)

filem = Menu(menubar)
filem.add_command(label = 'Open bin config',        command = load_config)
filem.add_command(label = 'Open xml config',        command = load_xmlconfig)
filem.add_command(label = 'Open CPE xml config',    command = load_cpexmlconfig)
filem.add_command(label = 'Save as bin config',     command = save_config, state = DISABLED)
filem.add_command(label = 'Save as xml config',     command = save_xmlconfig, state = DISABLED)
filem.add_command(label = 'Save as CPE xml config', command = save_cpexmlconfig, state = DISABLED)
filem.add_command(label = 'Exit',                   command = confquit)

menubar.add_cascade(label = 'File', menu = filem)

mainframe = ttk.Frame(root, padding="3 3 12 12")
mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
mainframe.columnconfigure(0, weight=1)
mainframe.rowconfigure(0, weight=1)

voip_user = StringVar()
voip_pass = StringVar()

voip_user.set("user")
voip_pass.set("pass")

voip_user_entry = ttk.Entry(mainframe, width=7, textvariable=voip_user)
voip_user_entry.grid(column=2, row=1, sticky=(W, E))

voip_pass_entry = ttk.Entry(mainframe, width=7, textvariable=voip_pass)
voip_pass_entry.grid(column=2, row=2, sticky=(W, E))

#ttk.Label(mainframe, textvariable=meters).grid(column=2, row=2, sticky=(W, E))

ttk.Label(mainframe, text="Voip username:").grid(column=1, row=1, sticky=W)
ttk.Label(mainframe, text="Voip password:").grid(column=1, row=2, sticky=W)
#ttk.Label(mainframe, text="meters").grid(column=3, row=2, sticky=W)

#ttk.Button(mainframe, text="Load Config", command=load_config).grid(column=1, row=3, sticky=W)
#ttk.Button(mainframe, text="Save Config", command=save_config).grid(column=2, row=3, sticky=W)
#ttk.Button(mainframe, text="Quit",        command=confquit).grid(column=3, row=3, sticky=W)


for child in mainframe.winfo_children(): child.grid_configure(padx=5, pady=5)

voip_user_entry.focus()
root.bind('<Return>', confquit)

root.mainloop()
