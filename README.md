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

Example:

    python3 pkcrypt.py sym_decrypt download.pem config.bin config.xml

## YAPL file structure

Yapl files are used as the CGI templates. This is just documentation that I
didn't know where else to put.

    0x00 - 0x03: Header "Yapl"
    0x04 - 0x07: Padding
    0x08 - 0x0B: Number of strings
    0x0C - 0x0F: Padding
    0x10 - ....: Zero separated strings
    .... - ....: Instructions that somehow reference the strings
