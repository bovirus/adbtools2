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
import queue
import logging
import signal
import tkinter as tk

from pathlib import Path
from tkinter import *
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk , VERTICAL, HORIZONTAL, N, S, E, W
from tkinter.filedialog import askopenfilename, asksaveasfilename
from Cryptodome.Cipher import AES # requires pycrypto
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
mydir    = sys.path[0]              # not correct on exe file from pyinstaller
mydir    = os.path.dirname(os.path.realpath(__file__))
down_pem = mydir + '/download.pem'
up_pem   = mydir + '/upload.pem'

randomstr  = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4))
tmpradix   = tempfile.gettempdir() + '/' + randomstr + '-'
tmpconf    = tmpradix + 'conf.xml'
tmpconfcpe = tmpradix + 'confcpe.xml'
fversion   = mydir + '/version'

homedir    = str(Path.home())
defaultdir = homedir
loaded_bin = 0                   # binary config loaded
loaded_xml = 0                   # xml config loaded
loaded_cpe = 0                   # cpe xml config loaded
versionstr = ''

load_pems_done = 0

def show_restricted():
    global cpedata_out
    sout = get_restricted(cpedata_out)
    logger.log(linfo,sout)

def save_restricted():
    global cpedata_out
    global defaultdir
    sout = get_restricted(cpedata_out)
    name = asksaveasfilename(initialdir=defaultdir,
                             filetypes =(("Text file", "*.txt"),("All Files","*.*")),
                             title = "Restricted text file"
                             )
    print (name)
    #Using try in case user types in unknown file or closes without choosing a file.
    try:
        with open(name,'w') as f:
            f.write(sout)
    except:
        print("Error writing: ",name)
        sys.exit(1)

    defaultdir=os.path.dirname(name)

#------------------------------------------------------------------------------
# get_restricted return a string with restricted commands in the cpe xml
#     input: xml_str it is cpedata_out
#------------------------------------------------------------------------------
def get_restricted(xml_str):
    global rtr_ip
    mystr   = re.sub(b'<!-- DATA.*', b'', xml_str, 0, re.DOTALL)
    xmltree = ET.parse(io.BytesIO(mystr))
    xmlroot = xmltree.getroot()

    sweb = '';
    scli = '';

    for i in xmlroot.findall(".//X_ADB_AccessControl/Feature/PagePath"):
        web = i.text
        parent = i.getparent()
        perm = ''
        for child in parent:
            if child.tag == 'Permissions':
                perm = child.text
        print(i.text)
        print(perm)

        if perm == '0000':
            print(web[0:4])
            if web[0:4] == 'dboa':
                sweb = sweb + "\n" + "    " + "http://" + rtr_ip.get() + "/ui/" + web
            else:
                scli = scli + "\n" + "    " + web
    sout="\nRestricted web urls\n" + sweb + "\n" + "\nRestricted CLI commands\n" + scli
    return(sout)


#------------------------------------------------------------------------------
#    <PagePath>dboard/storage/ftpserver</PagePath>
#    <Origin>CPE</Origin>
#    <Permissions>2221</Permissions>
#    <PagePath>clish/configure/management/webGui</PagePath>
#    <Origin>CPE</Origin>
#    <Permissions>0000</Permissions>

def enable_restricted_web():
    global cpedata_out
    cpedata_out = re.sub(b'(<PagePath>dboa\S+</PagePath>.\s+<Origin>\S+.\s+<Permissions>)0000',b'\g<1>2221',cpedata_out, 0, re.DOTALL)
    logger.log(lerr,"Enabled restricted web pages")
    
def enable_restricted_cli():
    global cpedata_out
    cpedata_out = re.sub(b'(<PagePath>clis\S+</PagePath>.\s+<Origin>\S+.\s+<Permissions>)0000',b'\g<1>2221',cpedata_out, 0, re.DOTALL)
    logger.log(lerr,"Enabled restricted commands in CLI")

#<Name>dlinkddns.com</Name>
#<Name>dlinkdns.com</Name>

def fix_dlinkddns():
    global cpedata_out
    cpedata_out = re.sub(b'<Name>dlinkdns.com</Name>',b'<Name>dlinkddns.com</Name>',cpedata_out, 0, re.DOTALL)
    logger.log(lerr,"Fixed dlinkdns -> dlinkddns")
    
#------------------------------------------------------------------------------
# get_info     setup router info textvariables
#     input    xml_str   binary string, xml or cpe xml conf file
#------------------------------------------------------------------------------
def get_info (xml_str):
    global  rtr_hwversion
    mystr   = re.sub(b'<!-- DATA.*', b'', xml_str, 0, re.DOTALL)
    xmltree = ET.parse(io.BytesIO(mystr))
    xmlroot = xmltree.getroot()

    sout = '';

    for i in xmlroot.findall(".//DeviceInfo/HardwareVersion"):
        rtr_hwversion.set(i.text)

    for i in xmlroot.findall(".//DeviceInfo/Manufacturer"):
        rtr_manufacturer.set(i.text)

    for i in xmlroot.findall(".//DeviceInfo/ModelName"):
        rtr_modelname.set(i.text)

    for i in xmlroot.findall(".//DeviceInfo/SerialNumber"):
        rtr_serial.set(i.text)

    for i in xmlroot.findall(".//DeviceInfo/X_DLINK_fw_upgr_permitted"):
        rtr_fwupgrade.set(i.text)

    for i in xmlroot.findall(".//DeviceInfo/X_DLINK_customer_ID"):
        rtr_customerid.set(i.text)

    for i in xmlroot.findall(".//DeviceInfo/X_DLINK_BsdGuiVisible"):
        rtr_bsdgui.set(i.text)

    for i in xmlroot.findall(".//DeviceInfo/X_DLINK_AllowFirmwareDowngrade"):
        rtr_fwdowngrade.set(i.text)

    for i in xmlroot.findall(".//IP/Interface/IPv4Address/IPAddress"):
        parent = i.getparent()
        granpa = parent.getparent()
        for child in granpa:
            if (child.tag == 'Alias') and (child.text == 'Bridge'):
                rtr_ip.set(i.text)

    for i in xmlroot.findall(".//IP/Interface/IPv4Address/SubnetMask"):
        parent = i.getparent()
        granpa = parent.getparent()
        for child in granpa:
            if (child.tag == 'Alias') and (child.text == 'Bridge'):
                rtr_mask.set(i.text)


#------------------------------------------------------------------------------
# get_passwords return a string text file with passwords xml string
#     input    xml_str   binary string, xml or cpe xml conf file
#     rturn    text string 
#------------------------------------------------------------------------------
def get_passwords (xml_str):
    mystr   = re.sub(b'<!-- DATA.*', b'', xml_str, 0, re.DOTALL)
    xmltree = ET.parse(io.BytesIO(mystr))
    xmlroot = xmltree.getroot()

    sout = '';
    
    for s in  [ 'AuthPassword', 'Password' ]:
        for i in xmlroot.findall(".//" + s):
            parent  = i.getparent()
            granpa  = parent.getparent()
            try: granpa2s = granpa.getparent().tag
            except: granpa2s=''
            if ((granpa2s != 'X_ADB_MobileModem') and i.text is not None):
                sout = sout + granpa2s + '/' + granpa.tag + '/' + parent.tag + "\n"
                for child in parent:
                    if (child.tag in ['Name', 'AuthUserName', 'Password', 'AuthPassword', 'Username',
                                      'Enable', 'Url', 'Alias', 'Hostname' ]):
                        sout = sout + "  " + "%-15s" % (child.tag) + "  " + child.text + "\n"

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
    global infom
    global editm
    global menubar
    global rtr_hwversion
    global rtr_manufacturer
    global rtr_modelname
    global rtr_serial
    global rtr_fwupgrade
    global rtr_customerid
    global rtr_bsdgui
    global rtr_fwdowngrade
    global rtr_ip
    global rtr_mask

    print("check_enable_menu - loaded_bin, loaded_xml, loaded_cpe",loaded_bin,loaded_xml,loaded_cpe)
    
    if ((loaded_bin == 1 ) or ((loaded_xml == 1) and (loaded_cpe == 1))):
        filem.entryconfig(4, state = NORMAL)     # save as bin config
        filem.entryconfig(5, state = NORMAL)     # save as xml config
        filem.entryconfig(6, state = NORMAL)     # save as cpe xml config
        editm.entryconfig(1, state = NORMAL)     # enable restricted webgui
        editm.entryconfig(2, state = NORMAL)     # enable restricted CLI commands
        editm.entryconfig(3, state = NORMAL)     # enable firmware downgrade        
        editm.entryconfig(4, state = NORMAL)     # enable fix dlinkdns -> dlinkddns        
    else:
        filem.entryconfig(4, state = DISABLED)   # save as bin config 
        filem.entryconfig(5, state = DISABLED)   # save as xml config
        filem.entryconfig(6, state = DISABLED)   # save as cpe xml config

    if ((loaded_bin == 1) or (loaded_xml == 1) or (loaded_cpe == 1)):
        infom.entryconfig(1, state = NORMAL)     # show passwords
        infom.entryconfig(3, state = NORMAL)     # save passwords
    else:
        infom.entryconfig(1, state = DISABLED)   # show passwords
        infom.entryconfig(3, state = DISABLED)   # save passwords

    if ((loaded_bin == 1) or (loaded_cpe == 1)):
        infom.entryconfig(2, state = NORMAL)     # show restricted commands
        infom.entryconfig(4, state = NORMAL)     # save restricted commands
    else:
        infom.entryconfig(2, state = DISABLED)   # show restricted commands
        infom.entryconfig(4, state = DISABLED)   # save restricted commands
        
        
    if ((loaded_bin == 0) and (loaded_cpe == 0)):
        rtr_hwversion.set('                   ')
        rtr_manufacturer.set('                   ')
        rtr_modelname.set('                   ')
        rtr_serial.set('                   ')
        rtr_fwupgrade.set('                   ')
        rtr_customerid.set('                   ')
        rtr_bsdgui.set('                   ')
        rtr_fwdowngrade.set('                   ')
        rtr_ip.set('                   ')
        rtr_mask.set('                   ')
        
    logger.log(level,"check_enable_menu - done")

#------------------------------------------------------------------------------
# load_pems - load pem files
#------------------------------------------------------------------------------
def load_pems():
    global pemconf_data, pemcpe_data
    try:
        with open(down_pem, "rb") as f:
            pemconf_data = f.read()
    except:
        print("Error opening: ", down_pem)
        sys.exit(1)

    try:
        with open(up_pem, "rb") as f:
            pemcpe_data = f.read()
    except:
        print("Error opening: ",up_pem)
        sys.exit(1)
        
    load_pems_done = 1
    logger.log(ldebug,"load pems done")
    logger.log(ldebug,"len 1: " + str(len(pemconf_data)))
    logger.log(ldebug,"len 2: " + str(len(pemcpe_data)))
    

#------------------------------------------------------------------------------
# about - 
#------------------------------------------------------------------------------
def about():
    global versionstr
    global fversion
    aboutstr=''
    aboutstr=aboutstr.join(["ADB Configuration Editor (confedit)\n",
                            "Copyright (c) 2018 Valerio Di Giampietro (main program)\n",
                            "Copyright (c) 2017 Gabriel Huber (decrypting algorithm)\n",
                            "Copyright (c) 2017 Benjamin Bertrand (windows interface)\n\n",
                            "License informations available in the LICENSE file\n\n",
                            "THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n",
                            "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n",
                            "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n",
                            "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n",
                            "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n",
                            "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n",
                            "SOFTWARE.\n\n"])

    if (versionstr == ''):
        with open(fversion,"r") as f:
            versionstr = f.read()
            logger.log(ldebug,"reading " + fversion)
    popupmsg('About', aboutstr + "Program version: " + versionstr + "\n")

#------------------------------------------------------------------------------
# enable_fw_upgrade   unable fw upgrade/downgrade 
#------------------------------------------------------------------------------
def enable_fw_upgrade():
    global cpedata_out
    cpedata_out = re.sub(b'<X_DLINK_fw_upgr_permitted>false</X_DLINK_fw_upgr_permitted>',
                         b'<X_DLINK_fw_upgr_permitted>true</X_DLINK_fw_upgr_permitted>',
                         cpedata_out,
                         0,
                         re.DOTALL)
    cpedata_out = re.sub(b'<X_DLINK_AllowFirmwareDowngrade>false</X_DLINK_AllowFirmwareDowngrade>',
                         b'<X_DLINK_AllowFirmwareDowngrade>true</X_DLINK_AllowFirmwareDowngrade>',
                         cpedata_out,
                         0,
                         re.DOTALL)
    get_info(cpedata_out)
    logger.log(lerr,"Enbabled firmware upgrade/downgrade")
    
#------------------------------------------------------------------------------
# load_config - load binary router configuration file - ok
#------------------------------------------------------------------------------
def load_config(*args):
    global data_out
    global cpedata_out
    global defaultdir
    global loaded_bin
    global loaded_xml
    global loaded_cpe
    global pemcpe_data
    global pem_data
    global xml_src
    global cpexml_src
    name = askopenfilename(initialdir=defaultdir,
                           filetypes =(("Configuration file", "*.bin"),("All Files","*.*")),
                           title = "Choose a file."
                           )
    logger.log(ldebug,"loading: " + name)
    xml_src.set(name)
    cpexml_src.set(name)
    
    #Using try in case user types in unknown file or closes without choosing a file.
    try:
        with open(name,'rb') as f:
            data_in = f.read()
    except:
        print("Error opening: ",name)
        sys.exit(1)

    defaultdir=os.path.dirname(name)
    logger.log(ldebug,"defaultdir: " + defaultdir)
    if (not load_pems_done):
        load_pems()

    logger.log(ldebug,"len data_in: " + str(len(data_in)))
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
        sys.exit(1)
    
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
    logger.log(ldebug,"load_config legth cpedata_out" + str(len(cpedata_out)))
    loaded_bin = 1
    loaded_xml = 0
    loaded_cpe = 0
    check_enable_menu()
    #print_passwords()
    get_info(cpedata_out)
    
#------------------------------------------------------------------------------
# load_xmlconfig - load xml router configuration file - ok
#------------------------------------------------------------------------------
def load_xmlconfig(*args):
    global defaultdir
    global loaded_bin
    global loaded_xml
    global loaded_cpe
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
        sys.exit(1)

    defaultdir=os.path.dirname(name)
    loaded_xml = 1
    loaded_bin = 0
    check_enable_menu()
    if (not load_pems_done):
        load_pems()
    xml_src.set(name)
    if (loaded_cpe == 0):
        cpexml_src.set('')
    #print_passwords()
    check_enable_menu()

    
#------------------------------------------------------------------------------
# load_cpexmlconfig - load cpe xml router configuration file - ok 
#------------------------------------------------------------------------------
def load_cpexmlconfig(*args):
    global defaultdir
    global cpedata_out
    global loaded_cpe
    global loaded_xml
    global loaded_bin
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
        sys.exit(1)

    defaultdir=os.path.dirname(name)
    loaded_cpe = 1
    loaded_bin = 0
    if (loaded_xml == 0):
        xml_src.set('')
    check_enable_menu()
    if (not load_pems_done):
        load_pems()
    cpexml_src.set(name)
    #print_passwords()
    get_info(cpedata_out)
    check_enable_menu()
                                    
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
        sys.exit(1)

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
        sys.exit(1)

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
    sys.exit(0)

#------------------------------------------------------------------------------
# not_yet - print in the console the not implemented yet message
#------------------------------------------------------------------------------
def not_yet(mstr=''):
    logger.log(lerr, mstr + "not implemented yet\n")
    popupmsg('Info','Not implemented yet')

#------------------------------------------------------------------------------
# Main program start - set TK GUI based on
# https://github.com/beenje/tkinter-logging-text-widget
# Copyright (c) 2017, Benjamin Bertrand
#------------------------------------------------------------------------------

LARGE_FONT = ("Verdana", 12)
NORM_FONT  = ("Helvetica", 10)
SMALL_FONT = ("Helvetica", 8)

logger = logging.getLogger(__name__)

class QueueHandler(logging.Handler):
    """Class to send logging records to a queue

    It can be used from different threads
    The ConsoleUi class polls this queue to display records in a ScrolledText widget
    """
    # Example from Moshe Kaplan: https://gist.github.com/moshekaplan/c425f861de7bbf28ef06
    # (https://stackoverflow.com/questions/13318742/python-logging-to-tkinter-text-widget) is not thread safe!
    # See https://stackoverflow.com/questions/43909849/tkinter-python-crashes-on-new-thread-trying-to-log-on-main-thread

    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(record)


class ConsoleUi:
    """Poll messages from a logging queue and display them in a scrolled text widget"""

    def __init__(self, frame):
        self.frame = frame
        # Create a ScrolledText wdiget
        self.scrolled_text = ScrolledText(frame, state='disabled', height=12)
        self.scrolled_text.grid(row=0, column=0, sticky=(N, S, W, E),padx=3,pady=3)
        self.scrolled_text.configure(font='TkFixedFont')
        self.scrolled_text.tag_config('INFO', foreground='black')
        self.scrolled_text.tag_config('DEBUG', foreground='gray')
        self.scrolled_text.tag_config('WARNING', foreground='orange')
        self.scrolled_text.tag_config('ERROR', foreground='red')
        self.scrolled_text.tag_config('CRITICAL', foreground='red', underline=1)
        # Create a logging handler using a queue
        self.log_queue = queue.Queue()
        self.queue_handler = QueueHandler(self.log_queue)
        #formatter = logging.Formatter('%(asctime)s: %(message)s')
        formatter = logging.Formatter('%(message)s')
        self.queue_handler.setFormatter(formatter)
        logger.addHandler(self.queue_handler)
        # Start polling messages from the queue
        self.frame.after(100, self.poll_log_queue)

    def display(self, record):
        msg = self.queue_handler.format(record)
        self.scrolled_text.configure(state='normal')
        self.scrolled_text.insert(tk.END, msg + '\n', record.levelname)
        self.scrolled_text.configure(state='disabled')
        # Autoscroll to the bottom
        self.scrolled_text.yview(tk.END)

    def poll_log_queue(self):
        # Check every 100ms if there is a new message in the queue to display
        while True:
            try:
                record = self.log_queue.get(block=False)
            except queue.Empty:
                break
            else:
                self.display(record)
        self.frame.after(100, self.poll_log_queue)


class FormUi:

    def __init__(self, frame):
        self.frame = frame
        # Create a combobbox to select the logging level
        values = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        self.level = tk.StringVar()
        ttk.Label(self.frame, text='Level:').grid(column=0, row=0, sticky=W, padx=3, pady=3)
        self.combobox = ttk.Combobox(
            self.frame,
            textvariable=self.level,
            width=25,
            state='readonly',
            values=values
        )
        self.combobox.current(0)
        self.combobox.grid(column=1, row=0, sticky=(W, E), padx=3, pady=3)
        # Create a text field to enter a message
        self.message = tk.StringVar()
        ttk.Label(self.frame, text='Message:').grid(column=0, row=1, sticky=W, padx=3, pady=3)
        ttk.Entry(self.frame, textvariable=self.message, width=25).grid(column=1, row=1, sticky=(W, E), padx=3, pady=3)
        # Add a button to log the message
        self.button = ttk.Button(self.frame, text='Submit', command=self.submit_message)
        self.button.grid(column=1, row=2, sticky=W, padx=3, pady=3)

    def submit_message(self):
        # Get the logging level numeric value
        lvl = getattr(logging, self.level.get())
        logger.log(lvl, self.message.get())


class RouterInfo:
    def __init__(self, frame):
        global rtr_hwversion
        global rtr_manufacturer
        global rtr_modelname
        global rtr_serial
        global rtr_fwupgrade
        global rtr_customerid
        global rtr_bsdgui
        global rtr_fwdowngrade
        global rtr_ip
        global rtr_mask
        
        self.frame = frame
        ttk.Label(self.frame, text='Hardware Version: ').grid(column=0, row=1, sticky=W)
        ttk.Label(self.frame, textvariable=rtr_hwversion).grid(column=1, row=1, sticky=W)

        ttk.Label(self.frame, text='Manufacturer: ').grid(column=0, row=2, sticky=W)
        ttk.Label(self.frame, textvariable=rtr_manufacturer).grid(column=1, row=2, sticky=W)
        
        ttk.Label(self.frame, text='Model Name: ').grid(column=0, row=3, sticky=W)
        ttk.Label(self.frame, textvariable=rtr_modelname).grid(column=1, row=3, sticky=W)

        ttk.Label(self.frame, text='Serial Number: ').grid(column=0, row=4, sticky=W)
        ttk.Label(self.frame, textvariable=rtr_serial).grid(column=1, row=4, sticky=W)

        ttk.Label(self.frame, text='Fw upgrade permitted: ').grid(column=0, row=5, sticky=W)
        ttk.Label(self.frame, textvariable=rtr_fwupgrade).grid(column=1, row=5, sticky=W)
        
        ttk.Label(self.frame, text='Router customer ID: ').grid(column=0, row=6, sticky=W)
        ttk.Label(self.frame, textvariable=rtr_customerid).grid(column=1, row=6, sticky=W)
        
        ttk.Label(self.frame, text='BSD GUI visible: ').grid(column=0, row=7, sticky=W)
        ttk.Label(self.frame, textvariable=rtr_bsdgui).grid(column=1, row=7, sticky=W)
        
        ttk.Label(self.frame, text='Fw downgrade permitted: ').grid(column=0, row=8, sticky=W)
        ttk.Label(self.frame, textvariable=rtr_fwdowngrade).grid(column=1, row=8, sticky=W)
        
        ttk.Label(self.frame, text='Router IP (bridge interface): ').grid(column=0, row=9, sticky=W)
        ttk.Label(self.frame, textvariable=rtr_ip).grid(column=1, row=9, sticky=W)
        
        ttk.Label(self.frame, text='Router Net Mask (bridge interface): ').grid(column=0, row=10, sticky=W)
        ttk.Label(self.frame, textvariable=rtr_mask).grid(column=1, row=10, sticky=W)
        
class ThirdUi:

    def __init__(self, frame):
        global xml_src_lbl
        global cpexml_src_lbl
        self.frame = frame
        ttk.Label(self.frame, text='Main XML config file source: ').grid(column=0, row=1, sticky=W)
        ttk.Label(self.frame, textvariable=xml_src).grid(column=1, row=1, sticky=W)

        ttk.Label(self.frame, text='CPE XML config file source: ').grid(column=0, row=2, sticky=W)
        ttk.Label(self.frame, textvariable=cpexml_src).grid(column=1, row=2, sticky=W)


class App:

    def __init__(self, root):
        global filem
        global infom
        global editm
        self.root = root
        root.title('ADB Config Editor')
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        # Create the panes and frames
        vertical_pane = ttk.PanedWindow(self.root, orient=VERTICAL)
        vertical_pane.grid(row=0, column=0, sticky="nsew", padx=3, pady=3)
        horizontal_pane = ttk.PanedWindow(vertical_pane, orient=HORIZONTAL)
        vertical_pane.add(horizontal_pane)
        form_frame = ttk.Labelframe(horizontal_pane, text="Router Info")
        form_frame.columnconfigure(1, weight=1, minsize=120)
        horizontal_pane.add(form_frame, weight=1)
        console_frame = ttk.Labelframe(horizontal_pane, text="Console")
        console_frame.columnconfigure(0, weight=1)
        console_frame.rowconfigure(0, weight=1)
        horizontal_pane.add(console_frame, weight=1)
        third_frame = ttk.Labelframe(vertical_pane, text="Configuration loading status")
        vertical_pane.add(third_frame, weight=1)
        # Initialize all frames
        self.form = RouterInfo(form_frame)
        self.console = ConsoleUi(console_frame)
        self.third = ThirdUi(third_frame)
        #self.clock = Clock()
        #self.clock.start()
        self.root.protocol('WM_DELETE_WINDOW', self.quit)
        self.root.bind('<Control-q>', self.quit)
        signal.signal(signal.SIGINT, self.quit)

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

        infom = Menu(menubar)
        infom.add_command(label = 'Show passwords',           command = print_passwords, state = DISABLED)
        infom.add_command(label = 'Show restricted commands', command = show_restricted, state = DISABLED)
        infom.add_command(label = 'Save passwords',           command = save_passwords, state = DISABLED)
        infom.add_command(label = 'Save restriced commands',  command = save_restricted, state = DISABLED)
        infom.add_command(label = 'About',                    command = about)
        menubar.add_cascade(label = 'Info', menu = infom)

        editm = Menu(menubar)
        editm.add_command(label = 'Enable restricted web gui',         command = enable_restricted_web, state = DISABLED)
        editm.add_command(label = 'Enable restricted CLI commands',    command = enable_restricted_cli, state = DISABLED)
        editm.add_command(label = 'Enable firmware upgrade/downgrade', command = enable_fw_upgrade, state = DISABLED)
        editm.add_command(label = 'Fix dlinkdns -> dlinkddns',         command = fix_dlinkddns, state = DISABLED)        
        editm.add_command(label = 'Preferences',                       command = not_yet)        
        menubar.add_cascade(label = 'Edit', menu = editm)

        
    def quit(self, *args):
        #self.clock.stop()
        self.root.destroy()
# def popup_bonus():
#     win = tk.Toplevel()
#     win.wm_title("Window")
    
#     l = tk.Label(win, text="Input")
#     l.grid(row=0, column=0)
    
#     b = ttk.Button(win, text="Okay", command=win.destroy)
#     b.grid(row=1, column=0)
                            
        
def popupmsg(title,msg):
    popup = tk.Toplevel()
    popup.wm_title(title)
    popup.columnconfigure(0, weight=1, minsize=150, pad=15)
    popup.rowconfigure(0, weight=1, minsize=50)
    l = ttk.Label(popup, text=msg, font=NORM_FONT)
    l.grid(row=0, column=0, padx=3, pady=3)
    b = ttk.Button(popup, text="Okay", command = popup.destroy)
    b.grid(row=1,column=0, padx=3, pady=3)
    # Gets the requested values of the height and widht.
    windowWidth = popup.winfo_reqwidth()
    windowHeight = popup.winfo_reqheight()
    print("Width",windowWidth,"Height",windowHeight)

    # Gets both half the screen width/height and window width/height
    positionRight = int(popup.winfo_screenwidth()/2 - windowWidth/2) - 300 + 100
    positionDown = int(popup.winfo_screenheight()/2 - windowHeight/2) + 100
    
    # Positions the window in the center of the page.
    popup.geometry("+{}+{}".format(positionRight, positionDown))
    

                                
def print_passwords():
    global data_out
    global cpedata_out
    if (('data_out' in globals()) and ((loaded_bin == 1) or (loaded_xml == 1))):
        logger.log(lerr,"\n---- passwords from main configuration file ----")
        logger.log(lwarn,get_passwords(data_out))
    else:
        logger.log(lerr,"\n---- Main configuration file not loaded ----")

    if (('cpedata_out' in globals()) and ((loaded_bin == 1) or (loaded_cpe == 1))):
        logger.log(lerr,"---- passwords from CPE configuration file ----")
        logger.log(lwarn,get_passwords(cpedata_out))
    else:
        logger.log(lerr,"\n---- CPE configuration file not loaded ----")
        
#-----------------------------------------------------------------------------------------------
# save_passwords  - save passwords to a text file
#-----------------------------------------------------------------------------------------------
def save_passwords():
    global data_out
    global cpedata_out
    global defaultdir
    
    pass_str = ''
    if (('data_out' in globals()) and ((loaded_bin == 1) or (loaded_xml == 1))):
        pass_str = pass_str + "---- passwords from main configuration file ----\n\n"
        pass_str = pass_str + get_passwords(data_out)
    else:
        pass_str = pass_str + "---- Main configuration file not loaded ----\n\n"

    if (('cpedata_out' in globals()) and ((loaded_bin == 1) or (loaded_cpe == 1))):
        pass_str = pass_str + "\n---- passwords from CPE configuration file ----\n\n"
        pass_str = pass_str + get_passwords(cpedata_out)
    else:
        pass_str = pass_str + "\n---- CPE configuration file not loaded ----\n"
        
    name = asksaveasfilename(initialdir=defaultdir,
                             filetypes =(("Text password file", "*.txt"),("All Files","*.*")),
                             title = "Choose a file."
                             )
    print (name)
    #Using try in case user types in unknown file or closes without choosing a file.
    try:
        with open(name,'w') as f:
            f.write(pass_str)
    except:
        print("Error writing: ",name)
        sys.exit(1)

    defaultdir=os.path.dirname(name)

        
#-----------------------------------------------------------------------------------------------
# Main Program
#-----------------------------------------------------------------------------------------------
        
logging.basicConfig(level=logging.DEBUG)
root = tk.Tk()
xml_src          = tk.StringVar()     # file loaded with main xml configuration
cpexml_src       = tk.StringVar()     # file loaded with cpe xml configuration
rtr_hwversion    = tk.StringVar()
rtr_manufacturer = tk.StringVar()
rtr_modelname    = tk.StringVar()
rtr_serial       = tk.StringVar()
rtr_fwupgrade    = tk.StringVar()
rtr_customerid   = tk.StringVar()
rtr_bsdgui       = tk.StringVar()
rtr_fwdowngrade  = tk.StringVar()
rtr_ip           = tk.StringVar()
rtr_mask         = tk.StringVar()

rtr_hwversion.set('                   ')
rtr_manufacturer.set('                   ')
rtr_modelname.set('                   ')
rtr_serial.set('                   ')
rtr_fwupgrade.set('                   ')
rtr_customerid.set('                   ')
rtr_bsdgui.set('                   ')
rtr_fwdowngrade.set('                   ')
rtr_ip.set('                   ')
rtr_mask.set('                   ')

xml_src.set('Not loaded')
cpexml_src.set('Not loaded')


app = App(root)

ldebug = logging.DEBUG
linfo  = logging.INFO
lwarn  = logging.WARNING
lerr   = logging.ERROR
lcri   = logging.CRITICAL

level=ldebug
logger.log(ldebug,"mydir:      " + mydir)
logger.log(ldebug,"down_pem:   " + down_pem)
logger.log(ldebug,"up_pem:     " + up_pem)
logger.log(ldebug,"tmpradix:   " + tmpradix)
logger.log(ldebug,"tmpconf:    " + tmpconf)
logger.log(ldebug,"tmpconfcpe: " + tmpconfcpe)
logger.log(ldebug,"homedir:    " + homedir)


# ---- center the main window
# Gets the requested values of the height and widht.
windowWidth = app.root.winfo_reqwidth()
windowHeight = app.root.winfo_reqheight()
print("Width",windowWidth,"Height",windowHeight)

# Gets both half the screen width/height and window width/height
positionRight = int(app.root.winfo_screenwidth()/2 - windowWidth/2) - 300
positionDown = int(app.root.winfo_screenheight()/2 - windowHeight/2)

# Positions the window in the center of the page.
app.root.geometry("+{}+{}".format(positionRight, positionDown))

app.root.mainloop()


#------------------------------------------------------------------------------
#------------------------------------------------------------------------------

