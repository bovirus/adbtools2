# ADB Tools 2 description

Tools for hacking ADB Epicentro routers, especially the D-Link
DVA-5592 distributed by Wind in Italy to his FTTC and Fiber
subscribers.

These tools are:

* **python3 scripts** to decrypt and modify the router configuration file
  to recover VOIP and other passwords in plain text and to enable
  hidden or disabled functions. These scripts are available in python
  source and in .exe compiled version for Windows. The .exe files don't
  require Python and related additional modules
* **hack-script.sh** used to automate the procedure to become root on the
  DVA-5592 router and to temporary enable (until next reboot) the upgrade with
  an unsigned firmware
* **mod-kit** a folder with a firmware modification kit for the DVA-5592 router.
 The kit includes a couple of bash scripts and support files to enable the
 modification of the root file system and the generation of an unsigned
 firmware file to be loaded into the router thanks to the above script

Python dependencies can be installed using

    pip3 install -r requirements.txt

Python3 scripts are based on adbtools forked from Gabriel Huber's repository
(https://github.com/Yepoleb/adbtools) and use some GUI elements by
Benjamin Bertrand (https://github.com/beenje/tkinter-logging-text-widget)

# Table of contents

- [ADB Tools 2 description](#adb-tools-2-description)
- [Table of contents](#table-of-contents)
- [Decrypt and modify the router configuration file](#decrypt-and-modify-the-router-configuration-file)
	- [confedit](#confedit)
	- [confbin2xml](#confbin2xml)
	- [confxml2bin](#confxml2bin)
	- [pkcrypt](#pkcrypt)
- [How to become root on the D-Link DVA-5592 router](#how-to-become-root-on-the-d-link-dva-5592-router)
	- [Get an unprivileged busybox command prompt](#get-an-unprivileged-busybox-command-prompt)
	- [The role of the *cm* daemon running with *root* privileges](#the-role-of-the-cm-daemon-running-with-root-privileges)
	- [Exploiting the *cm* daemon to run a script with *root* privileges](#exploiting-the-cm-daemon-to-run-a-script-with-root-privileges)
	- [hack-script.sh](#hack-scriptsh)
- [Firmware modification kit](#firmware-modification-kit)
	- [Firmware modification kit prerequisites](#firmware-modification-kit-prerequisites)
	- [Content of the firmware modification kit folder (mod-kit)](#content-of-the-firmware-modification-kit-folder-mod-kit)
	- [Script mod-kit-configure.sh](#script-mod-kit-configuresh)
	- [Script mod-kit-run.sh](#script-mod-kit-runsh)
- [Entware installation](#entware-installation)
- [Information source to develop these tools](#information-source-to-develop-these-tools)
- [YAPL file structure](#yapl-file-structure)
- [Author](#author)


# Decrypt and modify the router configuration file

The following Python3 scripts allows to decrypt and/or modify and encrypt
the binary router configuration, locally saved using the web interface.

This  allows to show hidden passwords, including the VOIP password, stored in the
encrypted configuration file and to modify the configuration file to enable
hidden or disabled functionalities.

## confedit

It is the main, GUI based, tool that allows:

* decryption of the router configuration
* extraction of the main XML configuration file and the CPE configuration file
* encryption of main XML configuration file and the XML CPE configuration file
* extraction of passwords embedded in the configuration files, including the
  VoIP username and password
* editing of various features including:
  - enable restricted web GUI elements
  - enable restricted CLI commands
  - enable firmware upgrade/downgrade
  - fix wrong ddns server: dlinkdns.con -> dlinkddns.com

## confbin2xml

It is an improved version of the pkcrypt tool (see below) used for
decrypting the config backup file saved from the router
webinterface.

The config backup file is a binary encrypted xml file
with a trailing segment of base64 encrypted CPE DATA as in the
following snippet:

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
text file in "unix format" (Line Feed as line separator) so notepad has
difficulties in displaying them correctly, you can use another editor
or convert them to "dos format" with a command similar to the
following:

    d:\adbtools2> type conf.xml | more /P > conf2.xml

in this way conf2.xml can be correctly viewed with notepad.

One interesting piece of information is the SIP username and password
in plain text in both configuration file as in the following conf.xml
snippet:

          <SIP>
                <AuthPassword>1234XABC</AuthPassword>
                <AuthUserName>39099123456</AuthUserName>
          </SIP>

## confxml2bin

Does the opposite of confbin2xml, takes, as input, the main XML configuration file, the CPE XML configuration file, the two encrypting keys and generates the encrypted binary XML file ready to be loaded into the router.

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


# How to become root on the D-Link DVA-5592 router

Previous known Epicentro vulnerabilities (like
https://www.exploit-db.com/exploits/44983/) has been closed in the
software version (\_ADB_PlatformSoftwareVersion=6.0.0.0028) used by this
router, so it was necessary to to search another unexploited vulnerability.

The procedure described here has been tested on the DVA-5592 router, probably
it will function on other Epicentro routers, eventually with some modifications.

## Get an unprivileged busybox command prompt

A telnet into this router gives a `/bin/clish` command
prompt. Clish (or Klish) si an open source project
(http://libcode.org/projects/klish/) to give a "Cisco like"
interface. This shell is configured through an xml configuration file.

Looking at the startup scripts (see below about router file system
analysis) and at the `/bin/clish` script it is possible to see that the normal
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
out and the router doesn't operate normally: DHCP server is not working,
WiFi has some esoteric, but unusable, SSIDs and Internet connection
doesn't work. It is needed to configure a static IP address on the PC to
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

## The role of the *cm* daemon running with *root* privileges

The result of file system analysis shows that large part of the
router configuration modification, in response to user's CLI commands or web
interaction, is done by a system process, `/sbin/cm`, running
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
`/tmp/cmctl`.

Also `clish` has a plugin to talk directly to `cm`
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

* in the above file there is the following xml snippet:
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

## Exploiting the *cm* daemon to run a script with *root* privileges

The interesting thing is that it is possible to re-configure the `cm`
daemon giving it, through cmclient, a command to load a
new XML file located, for example, in the /tmp folder. Each definition in a new
XML file overwrites existing definitions, This means that it is possible to:

* copy `/etc/cm/tr181/dom/Management.xml` into `/tmp`

* modify `/tmp/Managemente.xml` to load `../../tmp/Users.sh`
  (`/tmp/Users.sh`) instead of `Users.sh` (`/etc/ah/Users.sh`)

* give the command to reconfigure the `cm` daemon: `cmclient
  DOM Device /tmp/Management.xml`

* copy `/etc/ah/Users.sh` into `/tmp`

* modify `/tmp/Users.sh` to modify `/tmp/passwd` (`/etc/passwd` links
  to this file) to remove the '\*' from the root password field to
  allow `su - root` without password

* have `cm` execute the modified `/tmp/Users.sh` script with `root` privileges
  with the command: `cmclient ADD Device.Users.User`

## hack-script.sh

This is a script to be executed on the `/bin/ash` command line
interface in the router to exploit the above vulnerability and become
root.

This script does exactly the above steps, so to become root, in an unprivileged
busybox command prompt, it is needed to:

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

As *root*, it is now possible to modify everything, but I have found that
modifying the root jffs2 file system I start getting, on
the console, error messages related to jffs2 checksum errors. The root
jffs2 file system is mounted read/write, but the router firmware never
modify it, and treat it as if it was mounted read only. Only the
firmware upgrade procedure rewrites the root jffs2 file system.

I don't know why this happens, it seems (but not fully sure) that adding files
doesn't give checksum error messages, but modifying existing files does.

The `hack-script.sh` has another feature: the possibility to temporary upgrade
the router with an unsigned firmware file. To do so it

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
`sig_verify` is the executable used to check that the firmware file has been
digitally signed with the supplier's private key. The public key is embedded in
this executable file. This modification means that an unsigned firmware will
be treated as a signed one.

* execute the `mount --bind` command to temporary "replace"
  /usr/sbin/upgrade.sh and temporary (until reboot) allow an upgrade
  with an unsigned firmware:
```
su -c "mount --bind /tmp/upgrade.sh /usr/sbin/upgrade.sh" -
```
* after the execution of `hack-script.sh`, before reboot and still in "factory
mode" it is possible to upgrade, via web interface, the router with an unsigned
firmware generated with the "Firmware Modification Kit" described below.

To return to normal mode of operation it is needed to exit factory
mode with the following command in the clish shell

    DLINK# restore default-setting

The router will return to the normal mode, but the previous configuration has
been wiped out, so the router restarts as if it was resetted to factory
configuration.

# Firmware modification kit

This kit, located in the folder *mod-kit* in this repository, allows to
extract the root file system from an official firmware file, modify and/or
add new files to this root file system and generate a new, unsigned, firmware
file, ready to be uploaded to the router, via web interface, following the
procedure described above and involving the use of `hack-script.sh`.

Current implementation has the following limitations (some of them
may be removed in future releases):

* only the DVA-5592_A1_WI_20180405.sig firmware can be modified
  (firmware for the device D-Link DVA-5592 distributed in Italy by
  Wind and released on 2018/04/05)

* new root file system image, incorporating custom modifications, must
  not be greater than current root file system image size

* runs only on Linux (this limitation will not be removed in future
  releases)

## Firmware modification kit prerequisites

The kit requires some software to be available, the two most important
required software are:

* Jefferson available at https://github.com/sviehb/jefferson, to
  extract the jffs2 root file system from the JFFS2 image file

* mkfs.jffs2, part of mtd-utils
  (http://www.linux-mtd.infradead.org/source.html), with the lzma patch
  to support lzma compression. The version of mkfs.jffs2, usually
  available on package repositories, doesn't include the lzma patch. I
  grabbed the lzma patch from the openwrt project and included it in
  this repository.

To get mkfs.jffs2 with lzma support there are at least two
options: get a compiled version with the lzma patch included
from an OpenWRT SDK or compile the mtd-utils from source.

To compile the mtd-utils, some additional packages can be needed on
the Linux system used for compilation, for example, in my case, on my
Ubuntu 16.04.05, I had to install:

```
sudo apt install liblzo2-2 liblzo2-dev libacl1 libacl1-dev
```

If some errors pop-up during compilation it is always possible to
google the error and find what package is needed to install to resolve the
issue.

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

    # copy the mkfs.jffs2 command in a suitable location, for example
    sudo cp mkfs.jffs2 /usr/local/bin/mkfs.jffs2-lzma
```

## Content of the firmware modification kit folder (mod-kit)

The folder mod-kit contains the following files/directories:

* **mod-kit-configure.sh** this script prepare and create the
    directory tree (*mod-kit-dir*) that will contain the original firmware file,
    the original extracted root file system, the patch directory, the
    overlay directory, the new modified root file system, the new
    modified and unsigned firmware file. This is the first script to
    run.

* **mod-kit-run.sh** this is the main script that extracts the root
    file system from the original firmware, apply patches to it, apply
    overlay files, remove files listed in `root-rm-files.txt`, executes the
    `pre-image-script.sh` and generate the new unsigned firmware file.

* **device-table.txt** the device table used by `mkfs.jffs2` to allow
    creation of /dev/console and /dev/null in the jffs2 root file
    system image. This is needed because the normal user (not root), that runs
    this kit, has no rights to create a special device file. This file is
    copied to the *mod-kit-dir* and can be customized, if needed.

* **root-permissions.acl** this file contains the correct file owner
    and mode of each file in the root file system. This file is needed
    because files extracted by Jefferson haven't the correct file mode
    and ownership. This file is copied to the *mod-kit-dir* and can be
    customized, if needed.

* **mtd-utils-lzma_jffs2.patch** this is the patch to apply to
    mtd-utils to add support for lzma compression (see above)

* **root-patch** this is a directory with same folder structure as the
    root file system and a corresponding file for each file that needs
    to be patched on the original root file system. The patch file
    name is the same as the file to be patched with the suffix
    `.patch`. This directory is copied to the *mod-kit-dir* and can be
    customized, if needed. Currently only the following files will be patched:

    * **/etc/passwd.orig** to replace the `:*:` from the `root` entry, with a
        valid encrypted password field, the default password is **no.wordpass**,
        but can be changed passing a parameter to `mod-kit-run.sh`; this
        allows `su -` to root. Please note that `root`
        cannot login with telnet or ssh, and no login is allowed from
        Internet.

    * **/usr/sbin/upgrade.sh** to allow firmware upgrade with unsigned
        firmware file, using the web interface.

    * **/usr/sbin/usb_hotplug_sw_upgrade.sh** to allow firmware
        upgrade with unsigned firmware file, using a USB key.

    * **/etc/clish/startup.xml** to allow the command "system shell"
        in normal mode (currently this command is available only in
        factory mode). This command allows to escape the clish
        interface and use a standard /bin/ash (busybox) CLI.

* **root-overlay** this is a directory with same folder structure as
    the root file system, files present in this directory will be
    written to the new root file system, after the above patches have
    been applied. This directory is copied to the *mod-kit-dir* and can be
    customized. Currently the main folder and files located in this
    directory are the followings:

    * `/opt` directory, it is the mount point for an ext2, ext3 or ext4
      first partition on a USB key where to install *entware*
      (https://github.com/Entware)

    * `/etc/init.d/entware.sh` and related link files in `/etc/rc.d`
      (`K00entware.sh` and `S99entware.sh`). This script is executed on boot,
      with parameter "boot", and on shutdown, with parameter "shutdwon", and
      initializes or terminates the *entware* environment. It can be manually
      executed, with parameter "install" to install the *entware* environment
      on an available ext2, ext3 or ext4 first partition on an attached USB key
      (see below for instructions)

    * `/usr/bin/wget` it is needed for initial *entware* installation

    * `/usr/lib/libtirpc.so.3.0.0` and related links, they are needed by `wget`

* **root-rm-files.txt** this file lists, one per line, files and/or directories
    to be removed from the new root file system. '#' as first char in a line is
    a comment and it is ignored, a trailing '/' indicate a directory. This
    file is copied to the *mod-kit-dir* and can be customized.

* **pre-image-script.sh** this script will be executed just before the
    creation of the new root file system image and can be used to further
    sutomize the new root file system. By default it modifies the file
    `/etc/banner` to add a line identifying adbtools2 version and firmware
    build date. It is copied to the *mod-kit-dir* and can be customized.

## Script mod-kit-configure.sh

This script creates the directory tree where the firmware modification kit will
store original firmware file, original root file system, modified root file
system, modified and unsigned firmware file system and other support files.

Script usage is the following:
```
usage: ./mod-kit-configure.sh [ -d basedir ] [ -j /path/to/mkfs.jffs2 ] <firmware file>
   -d basedir (defautl $HOME/mod-kit)
   -j /path/to/mkfs.jffs2 (default /usr/local/bin/mkfs.jffs2-lzma)
   -h this help

   example:
   ./mod-kit-configure.sh /path/to/DVA-5592_A1_WI_20180405.sig
```

This script will create the following directories, and partially populate then,
under the *basedir* provided with the `-d` option (default is $HOME/mod-kit)

* **input** the original firmware file is copied to this directory, the original
  root file system images and other original intermediate images are stored on
  this directory

* **input/root** the original root file system, extracted with Jefferson by the
  `mod-kit-run.sh` script is stored there

* **output** the modified firmware file is generated, by `mod-kit-run.sh`, in
  this directory, intermediate modified file system images are stored in this
  directory

* **output/root** the modified root file system is stored in this directory.
  The original file system in `input/root` is copied here, then patches from
  `root-patch` directories are applied, then files in the `root-overlay`
  directory are copied here.

* **root-patch** this is a directory with same folder structure as the
  root file system and a corresponding file for each file that needs
  to be patched on the original root file system. The patch file
  name is the same as the file to be patched with the suffix
  `.patch`. This directory is initially populated by the `mod-kit-configure.sh`
  script from the similar directory in this repository. The user can customize
  this directory adding more patch files.

* **root-overlay** this is a directory with same folder structure as
  the root file system, files present on this directory will be
  written to the new root file system, after the above patches have
  been applied by the `mod-kit-run.sh` script. This directory is initially
  populated by the `mod-kit-configure.sh` script from the similar directory
  in this repository. The user can customize this directory adding more files
  and or directories.

* **device-table.txt**  the device table used by `mkfs.jffs2` to allow
  creation of /dev/console and /dev/null in the jffs2 root file
  system image. This is needed because the normal user (not root), that runs
  this kit, has no rights to create a special device file. This file is
  populated by the `mod-kit-configure.sh` script from the similar file
  in this repository.

* **root-permissions.acl** this file contains the correct file owner
  and mode of each file in the root file system. This file is needed
  because files extracted by Jefferson haven't the correct file mode
  and ownership. This file is populated by the `mod-kit-configure.sh` script
  from the similar file in this repository.

* **root-rm-files.txt** this file lists, one per line, files and/or directories
  to be removed from the new root file system. '#' as first char in a line is
  a comment and it is ignored, a trailing '/' indicate a directory. This
  file can be customized.

* **pre-image-script.sh** this script will be executed just before the
  creation of the new root file system image and can be used to further
  customize the new root file system. By default it modifies the file
  `/etc/banner` to add a line identifying adbtools2 version and firmware
  build date and can be customized.

## Script mod-kit-run.sh

This script does the main job to generate the modified unsigned firmware
file:

* extract the root file system image from the original firmware file
* extract the original file system from the image into `input/root`
* copy `input/root` to `output/root`
* apply patches from `root-patches` to `output/root`
* copy additional files/directory from `root-overlay` to `output/root`
* generate the new root file system image
* insert the new root file system image into the new unsigned firmware files
* if *xdelta3* is available, generate and *xdelta* file to binary patch the
  original firmware to obtain the new modified firmware file.

Usage of this script is the following:
```
usage: ./mod-kit-run.sh [ -c ] [ -h ] [-p password]
       -c             clean all generated files from a previous run
       -p password    set password for root, default 'no.wordpass'
       -h             print this help
```

# Entware installation

*Entware* (https://github.com/Entware/Entware) is a software repository for
embedded devices with more than 2000 packages and a package manager (*opkg*)
to easily install them and to automatically resolve dependencies.

*Entware* packages are installed under the `/opt` directory tree (in this case
this is the first ext2, ext3 or ext4 partition of an attached USB key) and use
libraries, configurations files etc. inside the `/opt` tree; this means that
*entware* remains in some way separated from the firmware installed on the
device and does not interfere much with the installed firmware.

To remove *entware* it is enough to unmount the `/opt` directory or to remove
everything from the USB key partition mounted on `/opt`.

To install *entware*, on a router running the modified firmware, it is needed
to:
  * attach an already formatted USB key with the first, or only, partition
    formatted with an ext2, ext3 or ext4 file system. Ext4 is preferred.

  * telnet to the router and executes the command `/etc/init.d/entware.sh`;
    usage of this command for installation is:
    ```
    /etc/init.d/entware.sh install [generic | alternative]
       generic:      do a standard installation (/opt/etc/passwd is a link to
                     system wide /etc/passwd)
       alternative:  do an alternative installation (/opt/etc/passwd is a file
                     with no relation to the system wide /etc/passwd)
    ```
    The difference between "standard" and "alternative" installation is
    explained in the *entware* web site. "Alternative" is recommended, and is
    the default, because if some software creates additional users during
    installation, it would get lost after reboot with a "standard" installation
    because the router keeps the system wide password in /tmp/passwd and this
    file is recreated at boot based on router configuration saved in XML files.

  * *entware* executables are installed in `/opt/bin` and `/opt/sbin` so, to be
    able to easily execute them, it is recommended to add these two directories
    to the PATH, it can be achieved sourcing /opt/etc/profile with
    ```
    root@dlinkrouter:~# . /opt/etc/profile
    ```
    please note that sourcing `/opt/etc/profile` puts `/opt/bin` and `/opt/sbin`
    as the first two directories of the PATH, so *entware* commands with
    same name as the firmware commands will take precedence. Sometimes it is
    not what expected.              

A successful *entware* installation is shown below:

```
valerio@ubuntu-hp:~/temp/entware$ telnet 192.168.1.1
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
root@dlinkrouter:~# /etc/init.d/entware.sh install alternative
entware.sh: fstype: ext3
entware.sh: module ext2 already loaded
entware.sh: module mbcache already loaded
entware.sh: module jbd already loaded
entware.sh: module jbd2 already loaded
entware.sh: module ext3 already loaded
entware.sh: module ext4 already loaded
entware.sh: /opt/etc/init.d/rc.unslung not found
entware.sh: entware software not found on /opt
entware.sh: Entware Installation
entware.sh: downloading http://bin.entware.net/armv7sf-k3.2/installer/alternative.sh
Connecting to bin.entware.net (81.4.123.217:80)
alternative.sh       100% |***************************************************************************************************************************|  2031   0:00:00 ETA
entware.sh: installing entware, executing /tmp/alternative.sh
Info: Checking for prerequisites and creating folders...
Warning: Folder /opt exists!
Info: Opkg package manager deployment...
Connecting to bin.entware.net (81.4.123.217:80)
opkg                 100% |***************************************************************************************************************************|   131k  0:00:00 ETA
Connecting to bin.entware.net (81.4.123.217:80)
opkg.conf            100% |***************************************************************************************************************************|   190   0:00:00 ETA
Connecting to bin.entware.net (81.4.123.217:80)
ld-2.27.so           100% |***************************************************************************************************************************|   135k  0:00:00 ETA
Connecting to bin.entware.net (81.4.123.217:80)
libc-2.27.so         100% |***************************************************************************************************************************|  1218k  0:00:00 ETA
Connecting to bin.entware.net (81.4.123.217:80)
libgcc_s.so.1        100% |***************************************************************************************************************************| 50840   0:00:00 ETA
Connecting to bin.entware.net (81.4.123.217:80)
libpthread-2.27.so   100% |***************************************************************************************************************************| 92648   0:00:00 ETA
Info: Basic packages installation...
Downloading http://bin.entware.net/armv7sf-k3.2/Packages.gz
Updated list of available packages in /opt/var/opkg-lists/entware
Installing busybox (1.28.3-2) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/busybox_1.28.3-2_armv7-3.2.ipk
Installing libc (2.27-8) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/libc_2.27-8_armv7-3.2.ipk
Installing libgcc (7.3.0-8) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/libgcc_7.3.0-8_armv7-3.2.ipk
Installing libssp (7.3.0-8) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/libssp_7.3.0-8_armv7-3.2.ipk
Installing librt (2.27-8) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/librt_2.27-8_armv7-3.2.ipk
Installing libpthread (2.27-8) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/libpthread_2.27-8_armv7-3.2.ipk
Configuring libgcc.
Configuring libc.
Configuring libpthread.
Configuring libssp.
Configuring librt.
Configuring busybox.
Installing entware-opt (227000-3) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/entware-opt_227000-3_all.ipk
Installing libstdcpp (7.3.0-8) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/libstdcpp_7.3.0-8_armv7-3.2.ipk
Installing entware-release (1.0-2) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/entware-release_1.0-2_all.ipk
Installing zoneinfo-asia (2018e-1) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/zoneinfo-asia_2018e-1_armv7-3.2.ipk
Installing zoneinfo-europe (2018e-1) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/zoneinfo-europe_2018e-1_armv7-3.2.ipk
Installing findutils (4.6.0-1) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/findutils_4.6.0-1_armv7-3.2.ipk
Installing terminfo (6.1-1) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/terminfo_6.1-1_armv7-3.2.ipk
Installing locales (2.27-8) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/locales_2.27-8_armv7-3.2.ipk
Installing grep (2.26-1) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/grep_2.26-1_armv7-3.2.ipk
Installing libpcre (8.41-2) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/libpcre_8.41-2_armv7-3.2.ipk
Installing opkg (2011-04-08-9c97d5ec-17b) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/opkg_2011-04-08-9c97d5ec-17b_armv7-3.2.ipk
Installing entware-upgrade (1.0-1) to root...
Downloading http://bin.entware.net/armv7sf-k3.2/entware-upgrade_1.0-1_all.ipk
Configuring terminfo.
Configuring libpcre.
Configuring grep.
Configuring locales.
Entware uses separate locale-archive file independent from main system
Creating locale archive - /opt/usr/lib/locale/locale-archive
Adding en_EN.UTF-8
Adding ru_RU.UTF-8
You can download locale sources from http://pkg.entware.net/sources/i18n_glib227.tar.gz
You can add new locales to Entware using /opt/bin/localedef.new
Configuring entware-upgrade.
Upgrade operations are not required
Configuring opkg.
Configuring zoneinfo-europe.
Configuring zoneinfo-asia.
Configuring libstdcpp.
Configuring entware-release.
Configuring findutils.
Configuring entware-opt.
Info: Congratulations!
Info: If there are no errors above then Entware was successfully initialized.
Info: Add /opt/bin & /opt/sbin to your PATH variable
Info: Add '/opt/etc/init.d/rc.unslung start' to firmware startup script for Entware services to start

This is an alternative Entware installation. We recomend to install and setup Entware version of ssh server
and use it instead of a firmware supplied one. You can install dropbear or openssh as an ssh server
root@dlinkrouter:~#
```

# Information source to develop these tools

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

# YAPL file structure

Yapl files are used as the CGI templates. This is just documentation that I
didn't know where else to put.

    0x00 - 0x03: Header "Yapl"
    0x04 - 0x07: Padding
    0x08 - 0x0B: Number of strings
    0x0C - 0x0F: Padding
    0x10 - ....: Zero separated strings
    .... - ....: Instructions that somehow reference the strings

# Author
I am happy to be contacted about this project, my contact details are:

|Item             |Content                                          |
|-----------------|-------------------------------------------------|
|Author's name    |Valerio Di Giampietro                            |
|Email            |v@ler.io (yes it's a valid email address!)       |
|Personal web site|http://va.ler.io (aka http://digiampietro.com)   |
|LinkedIn         |http://it.linkedin.com/in/digiampietro           |
|Twitter          |http://twitter.com/valerio                       |
|Facebook         |http://facebook.com/digiampietro                 |
