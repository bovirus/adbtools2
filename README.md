# ADB Tools

Tools for hacking ADB Epicentro routers, including the D-Link DVA-5592
distributed by Wind in Italy to his FTTC Home Fiber subscribers.

These tools are python3 scripts available in python source and in .exe
compiled version for Windows. The .exe doesn't require Python and
related additional modules, but please note that I use mainly Linux,
so the .exe version can be older than the python version.

Python dependencies can be installed using

    pip3 install -r requirements.txt

Based on adbtools by Gabriel Huber (https://github.com/Yepoleb/adbtools)

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

Python Usage example:

    python3 confbin2xml.py download.pem upload.pem config_full_DVA-5592_2018-06-04T222624.bin conf.xml confcpe.xml

Windows Usage example:

    d:\adbtools2> confbin2xml.exe download.pem upload.pem config_full_DVA-5592_2018-06-04T222624.bin conf.xml confcpe.xml

where:

    download.pem   input, decrypting key for the main configuration file, from the firmware file system
    upload.pem     input, decrypting key for the CPE Data configuration file, form the firmware file system
    config_full... input, configuration file downloaded from the router web interface
    conf.xml       output, main configuration file decrypted
    confcpe.xml    output, CPE Data configuration file decrypted

The output files written by the tool (conf.xml and confcpe.xml) are
text file in "unix format" (lf as line separator) so notped has
difficulties in displaying them correctly, you can use another editor
or convert them to "dos format" with a command similar to the
following:

    d:\adbtools2> cat conf.xml | more /P > conf2.xml

now conf2.xml can be correctly viewed with notepad.

One intersting piece of information is the SIP username and password
in plaintext in both configuration file as in the following conf.xml
fragment:

          <SIP>
                <AuthPassword>1234XABC</AuthPassword>
                <AuthUserName>39099123456</AuthUserName>
          </SIP>

## pkcrypt

Tool used for encrypting/decrypting the config backups from the
webinterface. Uses an RSA public key for AES encryption. Only works
with configs created with version E_3.4.0 or later (May 2017) as older
ones tried to use asymmetric encryption without a private key, which
makes the configs impossible to decrypt, even for the devices
themselves. Key can be found at `/etc/certs/download.pem` in the
firmware image.

Python usage example:

    python3 pkcrypt.py sym_decrypt download.pem config.bin config.xml

Windows usage example:

    d:\adbtools2> pkcrypt.exe sym_decrypt download.pem config.bin config.xml

## Information source to develop these tools

The information comes from the router file system analysis. The router
firmware available at
ftp://ftp.dlink.eu/Products/dva/dva-5592/driver_software/ has been
extracted using the binwalk (https://github.com/ReFirmLabs/binwalk)
and jefferson (https://github.com/sviehb/jefferson) firmware
extraction tools.

The file `backup-conf.sh` has been the main information source to
build these tools.

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
