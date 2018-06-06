# ADB Tools

Tools for hacking ADB Epicentro routers, including the D-Link DVA-5592
distributed by Wind in Italy to his FTTC Home Fiber subscribers.
Python dependencies can be installed using `pip3 install -r
requirements.txt`.

Based on adbtools by Gabriel Huber (https://github.com/Yepoleb/adbtools)

## pkcrypt

Tool used for encrypting/decrypting the config backups from the
webinterface. Uses an RSA public key for AES encryption. Only works
with configs created with version E_3.4.0 or later (May 2017) as older
ones tried to use asymmetric encryption without a private key, which
makes the configs impossible to decrypt, even for the devices
themselves. Key can be found at `/etc/certs/download.pem` in the
firmware image.

Usage example:

    python3 pkcrypt.py sym_decrypt download.pem config.bin config.xml

## confbin2xml.py

Tool used for decrypting the config backup file from the
webinterface. The config backup file is a binary encrypted xml file
with a trailing segment of base64 encrypted CPE DATA as in the following excerpt:

````

  \<\!-- CPE Data: DVA-5592/DVA-5592 system type    : 963138_VD5920 -->
  \<\!-- DATA
  9V/jO+TpbscUypF/41d3Ej15nwHuUp+c4wBWV4uFWb1Zb/nS6QuDiLUoZeJ2s0mksjXrARR2
  6+4XkU8c2Dt+0svzS01nAOYY6hEhWkiQhUUROsUg69qK88UvBHAiDXW0koIkZ2aOva4bci+U
  ....
  24g6a+nGht0O4xs99XXewI5uq0i/7+sf1Ic7CkscNfrS7k0n07MFPLWSV97kkmU1/+GfGwrd
  e1ICfokPdjY=
  \-\-\>

````

The confbin2xml.py tool extract and decrypt both files, they have
similar, but not identical, content. I suppose that the two contents
have to be consistent.

Usage example:

    python3 confbin2xml.py download.pem upload.pem config_full_DVA-5592_2018-06-04T222624.bin conf.xml confcpe.xml

where:

    download.pem   input, decrypting key for the main configuration file, from the firmware file system
    upload.pem     input, decrypting key for the CPE Data configuration file, form the firmware file system
    config_full... input, configuration file downloaded from the router web interface
    conf.xml       output, main configuration file decrypted
    confcpe.xml    output, CPE Data configuration file decrypted

One intersting piece of information is the SIP username and password
in plaintext in both configuration file as in the following conf.xml
fragment:

          <SIP>
                <AuthPassword>1234XABC</AuthPassword>
                <AuthUserName>39099123456</AuthUserName>
          </SIP>

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
