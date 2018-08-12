# ADB Tools 2

Tools for hacking ADB Epicentro routers, including the D-Link DVA-5592
distributed by Wind in Italy to his FTTC Home Fiber subscribers.

These tools are python3 scripts available in python source and in .exe
compiled version for Windows. The .exe doesn't require Python and
related additional modules, but please note that I use mainly Linux,
so the .exe version can be older than the python version.

There is also a bash shell script to be executed on the router to
exploit a vulnerability and become root.

Python dependencies can be installed using

    pip3 install -r requirements.txt

Based on adbtools by Gabriel Huber (https://github.com/Yepoleb/adbtools).
Using some gui elements by Benjamin Bertrand (https://github.com/beenje/tkinter-logging-text-widget)

## confedit

It is the main, gui based, tool that allows:

* decryption of the router configuration
* extraction of the main XML configuration file and the CPE configuration file
* encryption of main XML configuration file and the XML CPE configuration file
* extraction of passwords embedded in the configuration files, including the VoIP username and password
* editing of various features including:
  * enable restricted web gui elements
  * enable restricted CLI commands
  * enable firmware upgrade/downgrade
  * fix wrong ddns server: dlinkdns.con -> dlinkddns.com

## confbin2xml

It is an improved version of the pkcrypt tool (see below) used for
decrypting the config backup file saved from the router
webinterface.

The config backup file is a binary encrypted xml file
with a trailing segment of base64 encrypted CPE DATA as in the
following excerpt:

````

  <!-- CPE Data: DVA-5592/DVA-5592 system type    : 963138_VD5920 -->
  <!-- DATA
  9V/jO+TpbscUypF/41d3Ej15nwHuUp+c4wBWV4uFWb1Zb/nS6QuDiLUoZeJ2s0mksjXrARR2
  6+4XkU8c2Dt+0svzS01nAOYY6hEhWkiQhUUROsUg69qK88UvBHAiDXW0koIkZ2aOva4bci+U
  ....
  24g6a+nGht0O4xs99XXewI5uq0i/7+sf1Ic7CkscNfrS7k0n07MFPLWSV97kkmU1/+GfGwrd
  e1ICfokPdjY=
  -->

````

The confbin2xml.py tool extract and decrypt both files, they have
similar, but not identical, content. I suppose that the two contents
have to be consistent.

**Python Usage example:**

    python3 confbin2xml.py download.pem upload.pem config_full_DVA-5592_2018-06-04T222624.bin conf.xml confcpe.xml

**Windows Usage example:**

    d:\adbtools2> confbin2xml.exe download.pem upload.pem config_full_DVA-5592_2018-06-04T222624.bin conf.xml confcpe.xml

where:

    download.pem   input, decrypting key for the main configuration file, from the firmware file system
    upload.pem     input, decrypting key for the CPE Data configuration file, form the firmware file system
    config_full... input, configuration file downloaded from the router web interface
    conf.xml       output, main configuration file decrypted
    confcpe.xml    output, CPE Data configuration file decrypted

The output files written by the tool (conf.xml and confcpe.xml) are
text file in "unix format" (lf as line separator) so notepad has
difficulties in displaying them correctly, you can use another editor
or convert them to "dos format" with a command similar to the
following:

    d:\adbtools2> type conf.xml | more /P > conf2.xml

now conf2.xml can be correctly viewed with notepad.

One intersting piece of information is the SIP username and password
in plaintext in both configuration file as in the following conf.xml
fragment:

          <SIP>
                <AuthPassword>1234XABC</AuthPassword>
                <AuthUserName>39099123456</AuthUserName>
          </SIP>

## confxml2bin
Does the opposit of confbin2xml, takes, as input, the main XML configuration file, the CPE XML configuration file, the two encrypting keys and generates the encrypted binary XML file ready to be loaded into the router.

Using confbin2xml and confxml2bin it is possible to extract the two XML files, modify them and generate the new encrypted binary XML file, ready to be loaded into the router.

**Python usage example:**

  python3 confxml2bin.py download.pem upload.pem conf.xml confcpe.xml conf.bin
  
**Windows usage example:**
  
  d:\adbtools2> confxml2bin.exe download.pem upload.pem conf.xml confcpe.xml conf.bin
  
**where:**

    download.pem   input, encrypting key for the main configuration file, from the firmware file system
    upload.pem     input, encrypting key for the CPE Data configuration file, form the firmware file system
    conf.xml       input, main configuration file
    confcpe.xml    input, CPE Data configuration file
    conf.bin       output, configuration file ready to be uploaded to the router web interface


## pkcrypt

Tool used for encrypting/decrypting the config backups from the
webinterface. Uses an RSA public key for AES encryption. Only works
with configs created with version E_3.4.0 or later (May 2017) as older
ones tried to use asymmetric encryption without a private key, which
makes the configs impossible to decrypt, even for the devices
themselves. Key can be found at `/etc/certs/download.pem` in the
firmware image.

**Python usage example:**

    python3 pkcrypt.py sym_decrypt download.pem config.bin config.xml

**Windows usage example:**

    d:\adbtools2> pkcrypt.exe sym_decrypt download.pem config.bin config.xml

## hack-script.sh

This is a script to be executed on the `/bin/ash` command line
interface in the router to exploit a vulnerability and become
root. Details on how to use this script are in the following section.

## How to become root on this router

Previous known Epicentro vulnerabilities (like
https://www.exploit-db.com/exploits/44983/) has been closed in this
version of software (_ADB_PlatformSoftwareVersion=6.0.0.0028) so I was
forced to search another unexploited vulnerability.

### How to get an unprivileged busybox command prompt

When you telnet into this router you get a `/bin/clish` command
prompt. Clish (or Klish) si an open source project
(http://libcode.org/projects/klish/) to give a "Cisco like"
interface. This shell is configured through an xml configuration file;
looking at the startup scripts (see below about router file system
analysis) and at the `/bin/clish` script you can see that the normal
configuration file is `/tmp/clish/startup.xml` (`/tmp/clish` links to
`/etc/clish` in "normal" mode and to `/etc/clish/prod` in "factory
mode"), in this file there is an "hidden" command that isn't
auto-completed and doesn't show in the clish CLI:

```
   <COMMAND name="factory-mode" help="hidden">
      <ACTION>
	   cmclient DUMPDM FactoryData /tmp/cfg/FactoryData.xml > /dev/null
	   nvramUpdate Feature 0x2 > /dev/null
	   cmclient REBOOT > /dev/null
      </ACTION>
   </COMMAND>
```				
So it is possible to enter "factory-mode" with the following commands:

    valerio@ubuntu-hp:~$ telnet 192.168.1.1 
    Trying 192.168.1.1... 
    Connected to 192.168.1.1. 
    Escape character is '^]'. 
    Login: admin 
    Password: 

    ******************************************** 
    *                 D-Link                   * 
    *                                          * 
    *      WARNING: Authorised Access Only     * 
    ******************************************** 

    Welcome 
    DLINK# factory 
    DLINK(factory)# factory-mode 
    DLINK(factory)# 
    DLINK(factory)# Connection closed by foreign host. 
    valerio@ubuntu-hp:~$  

The system reboots and enters factory mode. The configuration is wiped
out and the router doesn'operate normally: DHCP server is not working,
WiFi has some esoteric, but unusable, SSIDs and Internet connection
doesn't work. You have to configure a static IP address on your PC to
communicate with the router's default IP (192.168.1.1).

But in this mode it is possible to enter an unprivileged busybox
shell:

    valerio@ubuntu-hp:~$ telnet 192.168.1.1 
    Trying 192.168.1.1... 
    Connected to 192.168.1.1. 
    Escape character is '^]'. 
    Login: admin 
    Password: 

    ******************************************** 
    *                 D-Link                   * 
    *                                          * 
    *      WARNING: Authorised Access Only     * 
    ******************************************** 

    Welcome 
    DLINK# system shell 


    BusyBox v1.17.3 (2018-04-11 12:29:54 CEST) built-in shell (ash) 
    Enter 'help' for a list of built-in commands. 

    /root $ 

### The role of the `cm` daemon running with `root` privileges

Based on filesystem analysis I have discovered that large part of the
router configuration is done by a system process, `/sbin/cm`, running
with root privileges:

    /root $ ps -ef | egrep 'PID| cm' 
    PID USER       VSZ STAT COMMAND 
    356 0         2560 S    cm  

This process (`cm` probably means "Configuration Manager") is started
by `/etc/init.d/services.sh` startup script, it is a daemon listening
for commands on the socket file `/tmp/cmctl`.

Commands are given using the `cmclient` configuration command, it is
not a program but it is interpreted directly by busybox probably
through a compiled plugin. `cmclient` simply writes commands to
`/tmp/cmctl`. Also `clish` has a plugin to talk directly to `cm`
through the `/tmp/cmctl` socket file.

During the router boot `cmclient` is used by startup files to
configure the `/sbin/cm` process giving it location of xml
configuration files.

During normal operations `cmclient` is executed by the web interface
or the clish CLI in response to user's request to get configuration
information or to change configuration parameters; in these cases
`cmclient` is executed by an unprivileged user (the web interface runs
as user `nobody`, the CLI runs, usually, as user `admin`).

The daemon `cm`, to change router configuration, uses "helper scripts"
located in the `/etc/ah` folder; so, for example, to add a new user or to
change current user's password it executes the helper script
`/etc/ah/Users.sh` passing it the correct parameters.

The `cm` process knows that it has to call `/etc/ah/Users.sh` through:

* a startup script that executes the command:
```
  cmclient DOM Device /etc/cm/tr181/dom/
```
* the `cm` daemon process every file in the above folder, including
  `/etc/cm/tr181/dom/Management.xml`

* in the above file it is included the following xml snippet:
```
    <object name="Users.User.{i}." 
          access="readOnly" 
          minEntries="0" 
          maxEntries="unbounded" 
          numEntriesParameter="UserNumberOfEntries" 
          enableParameter="Enable" 
          set="Users.sh" 
          add="Users.sh" 
          del="Users.sh"
    >
```
* the `cm` daemon prepend the `/etc/ah/` path in front of `Users.sh`

### Exploiting the `cm` daemon to run our script with `root` privileges

The interesting thing is that it is possible to re-configure the `cm`
daemon configuration giving it, through cmclient, a command to load a
new XML file located, for example, in the /tmp folder. This means that
it is possible to:

* copy `/etc/cm/tr181/dom/Management.xml` into `/tmp`

* modify `/tmp/Managemente.xml` to load `../../tmp/Users.sh`
  (`/tmp/Users.sh`) instead of `Users.sh` (`/etc/ah/Users.sh`)

* copy `/etc/ah/Users.sh` into `/tmp`

* modify `/tmp/Users.sh` to modify `/tmp/passwd` (`/etc/passwd` links
  to this file) to remove the '*' from the root password field to
  allow `su - root` without password

* give the command to reconfigure the `cm` daemon: `cmclient
  DOM Device /tmp/Management.xml`
   

* force the execution of our modified `/tmp/Users.sh` script with the
  command: `cmclient ADD Device.Users.User`

The script `hack-script.sh` does exactly the above steps, so to become
root you have to:
```
    /root $ cat > /tmp/hack-script.sh
       do a copy and paste of the script
       press CTRL-D to terminate the copy

    /root $ chmod a+x /tmp/hack-script.sh
    /root $ /tmp/hack-script.sh

    ....

    /root $ su -


    BusyBox v1.17.3 (2018-04-11 12:29:54 CEST) built-in shell (ash)
    Enter 'help' for a list of built-in commands.

	  ___           ___           ___           ___     
	 |\__\         /\  \         /\  \         /\  \    
	 |:|  |       /::\  \       /::\  \       /::\  \   
	 |:|  |      /:/\:\  \     /:/\:\  \     /:/\:\  \  
	 |:|__|__   /::\~\:\  \   /::\~\:\  \   _\:\~\:\  \ 
	 /::::\__\ /:/\:\ \:\__\ /:/\:\ \:\__\ /\ \:\ \:\__\
	/:/~~/~    \/__\:\/:/  / \/__\:\/:/  / \:\ \:\ \/__/
       /:/  /           \::/  /       \::/  /   \:\ \:\__\  
       \/__/            /:/  /         \/__/     \:\/:/  /  
		       /:/  /                     \::/  /   
		       \/__/                       \/__/    r41358.07b1b3a7  
    ..................................................................
     yet another purposeful solution by  Advanced Digital Broadcast SA
    ..................................................................
    root@localhost:~# id
    uid=0(root) gid=0(root) groups=0(root),19(remoteaccess),20(localaccess)
    root@localhost:~# 
```
You are now root, you could modify everything, but I have found that
if you modify the root jffs2 file system you will start getting, on
the console, error messages related to jffs2 checksum errors. The root
jffs2 file system is mounted read/write, but the router firmware never
modify it, and treat it as if it was mounted read only. Only the
firmware upgrade procedure rewrites the root jffs2 file system.

The `hack-script.sh` enable, also, the possibility to upgrade the
router with an unsigned firmware file. To do so it

* copy the /usr/sbin/upgrade.sh in /tmp/upgrade.sh and replace the
  following snippet
```
sig_verify $file 2> /dev/null
ret_code=$?
```
  with
```
sig_verify $file 2> /dev/null
ret_code=0
```
  this means that an unsigned firmware will be treated as a signed
  firmware

* execute the `mount --bind` command to temporary "replace"
  /usr/sbin/upgrade.sh and temporary (until reboot) allow an upgrade
  with an unsigned firmware:
```
su -c "mount --bind /tmp/upgrade.sh /usr/sbin/upgrade.sh" -
```

To return to router normal mode of operation you have to exit factory
mode with the following command in the clish shell

    DLINK# restore default-setting 

You will return to the normal mode, but the previous configuration has
been wiped out, so the router restart as if it was resetted to factory
configuration.

# Firmware modification kit

In the folder `mod-kit` there are a couple of scripts and support
files to modify an official firmware with another that includes our
modifications.

The scripts allow to extract the root file system from the official
firmware, apply our patches on this file system, overwrite exiting
files or add new files to the file system and then generate a new
unsigned firmware file that can be loaded into the router using the
`hack-script.sh` and the procedure to become root described above.

Current implementation has the following limitations (some of them
will be removed in future releases):

* only the DVA-5592_A1_WI_20180405.sig firmware can be modified
  (firmware for the device D-Link DVA-5592 ditributed in Italy by
  Wind)

* new root file image, incorporating our modifications, must not be
  greater than current root file image size

* runs only on Linux (this limitation will not be removed in future
  releases)

## Firmware modification kit prerequisites

The kit requires some software to be available, the two most important
required software are:

* Jefferson available at https://github.com/sviehb/jefferson, to
  extract the jffs2 root file system from the firmware file

* mkfs.jffs2, part of mtd-utils
  (http://www.linux-mtd.infradead.org/source.html) with the lzma patch
  to support lzma compression. The version of mkfs.jffs2, usually
  available on package repositories, doesn't include the lzma patch. I
  grabbed the lzma patch from the openwrt project and included it in
  this repository.

To get mkfs.jffs2 with lzma support there are at least two
possibilities: get a compiled version with the lzma patch included
from an OpenWRT SDK or compile the mtd-utils from source.

To compile the mtd-utils, some additional packages can be needed on
the Linux system used for compilation, for example, in my case, on my
Ubuntu 16.04.05, I had to install:

```
sudo apt install liblzo2-2 liblzo2-dev libacl1 libacl1-dev
```

If some errors pop-up during compilation it is always possible to
google the error and find what package is needed to resolve the issue.

To compile mtd-utils and apply the lzma patch included in this
repository I did:

```
# get the mtd-utils version v2.0.2 (last stable version, currently)
git clone -b v2.0.2 --single-branch --depth 1 git://git.infradead.org/mtd-utils.git

# apply the lzma patch included in this repository
cd mtd-utils/
patch -p1  < /path/to/this/repository/mod-kit/mtd-utils-lzma_jffs2.patch

# build the mtd-utils packages
./autogen.sh
./configure
make

# check that lzma compression is included
./mkfs.jffs2 -L
mkfs.jffs2: error!: 
      zlib priority:80 enabled
      lzma priority:70 enabled
     rtime priority:50 enabled

# copy the mkfs.jffs2 command in a suitable location
sudo cp mkfs.jffs2 /usr/local/bin/mkfs.jffs2-lzma
```


## Information source to develop these tools

The information comes from the router file system analysis. The router
firmware available at
`ftp://ftp.dlink.eu/Products/dva/dva-5592/driver_software/` has been
extracted using the binwalk (https://github.com/ReFirmLabs/binwalk)
and jefferson (https://github.com/sviehb/jefferson) firmware
extraction tools.

The file `/usr/sbin/backup-conf.sh` has been the main information source to
build these tools.

To become root the main source of information has been the clish
configuration files (the normal clish configuragion file
`/etc/clish/startup.xml` and factory mode configuration file
`/etc/clish/prod/startup.xml`) and startup scripts in `/etc/init.d`,
especially `/etc/init.d/services.sh`.

## YAPL file structure

Yapl files are used as the CGI templates. This is just documentation that I
didn't know where else to put.

    0x00 - 0x03: Header "Yapl"
    0x04 - 0x07: Padding
    0x08 - 0x0B: Number of strings
    0x0C - 0x0F: Padding
    0x10 - ....: Zero separated strings
    .... - ....: Instructions that somehow reference the strings

## Author
I am happy to be contacted about this project, my contact details are:

|Item             |Content                                          |
|-----------------|-------------------------------------------------|
|Author's name    |Valerio Di Giampietro                            |
|Email            |v@ler.io (yes it's a valid email address!)       |
|Personal web site|http://va.ler.io (aka http://digiampietro.com)   |
|LinkedIn         |http://it.linkedin.com/in/digiampietro           |
|Twitter          |http://twitter.com/valerio                       |
|Facebook         |http://facebook.com/digiampietro                 |
