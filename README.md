# SoftHSM

SoftHSM is part of the OpenDNSSEC project. Read more at www.opendnssec.org

## Introduction

OpenDNSSEC handles and stores its cryptographic keys via the PKCS#11 interface.
This interface specifies how to communicate with cryptographic devices such as
HSM:s (Hardware Security Modules) and smart cards. The purpose of these devices
is, among others, to generate cryptographic keys and sign information without
revealing private-key material to the outside world. They are often designed to
perform well on these specific tasks compared to ordinary processes in a normal
computer.

A potential problem with the use of the PKCS#11 interface is that it might
limit the wide spread use of OpenDNSSEC, since a potential user might not be
willing to invest in a new hardware device. To counter this effect, OpenDNSSEC
is providing a software implementation of a generic cryptographic device with a
PKCS#11 interface, the SoftHSM. SoftHSM is designed to meet the requirements of
OpenDNSSEC, but can also work together with other cryptographic products
because of the PKCS#11 interface.

## Dependencies

SoftHSM depends on the Botan 1.8.0 or greater (a cryptographic library) and
SQLite 3.3.9 or greater (a database library). But it is recommended to use
Botan 1.8.5 or greater since there is a known issues on some OS which freezes
the application when it tries to pull entropy. If the packaged version for your
distribution does not work try to compile the latest version from source. They
can be found at: http://botan.randombit.net and http://www.sqlite.org.

## Installing

### Bulding and 

Configure the installation/compilation scripts:

    ./configure

_Options:_

    --with-botan=PATH       Specify prefix of path of Botan
    --with-sqlite3=PATH     Specify prefix of path of SQLite3
    --enable-64bit          Compile a 64-bit version
    --with-loglevel=INT     The log level. 0=No log 1=Error 2=Warning 
                            3=Info 4=Debug (default INT=3)
    --prefix=DIR            The installation directory
                            (default DIR=/usr/local)

_For more options:_

    ./configure --help

Compile the source code:

    make

Install the library:

    sudo make install


## Configuring

### Add the tokens to the slots

The default location of the config file is /etc/softhsm.conf. This location can
be change by setting the environment variable.

    export SOFTHSM_CONF=/home/user/config.file

Open the config file and add the slots and tokens.

    pico /home/user/config.file

    0:/home/user/my.db
    # Comments can be added
    4:/home/user/token.database

**Note:** The token databases does not exist at this stage. The given paths are
just an indication to SoftHSM on where it should store the information for each
token. Each token are now treated as uninitialized.

### Initialize your tokens

Use either the softhsm tool or the PKCS#11 interface. The SO PIN can e.g. be
used to re-initialize the token and the user PIN is handed out to the
application so it can interact with the token.

    softhsm --init-token --slot 0 --label "My token 1"

Type in SO PIN and user PIN.

    softhsm --init-token --slot 4 --label "A token"

Type in SO PIN and user PIN.

### Using the library

Link to libsofthsm.so and use the PKCS#11 interface.


## Key Management

It is possible to export and import keys to libsofthsm.

###  Importing a key pair

Use the PKCS#11 interface or the softhsm tool where you specify the path to the
key file, slot number, label and ID of the new objects, and the user PIN. The
file must be in PKCS#8 format.
    
    softhsm --import key1.pem --slot 1 --label "My key" --id A1B2 --pin 123456

Add, --file-pin PIN, if the key file is encrypted. Use, softhsm --help, for
more info.

####  Exporting a key pair

All keys can be exported from the token database by using the softhsm tool. The
file will be exported in PKCS#8 format.

    softhsm --export key2.pem --slot 1 --id A1B2 --pin 123456

Add, --file-pin PIN, if you want to output an encrypted file. Use, softhsm
--help, for more info.


## Converting Keys to/from BIND

The softhsm-keyconv tool can convert keys between BIND .private-key format and
PKCS#8 key file format.

### Convert from BIND .private to PKCS#8

Keys used for DNSSEC in BIND can be converted over to PKCS#8. Thus possible to
import them into SoftHSM.

    softhsm-keyconv --topkcs8 --in Kexample.com.+007+05474.private --out rsa.pem

Add, --pin PIN, if you want an encrypted PKCS#8 file. Use, softhsm-keyconv
--help, for more info.

### Convert from PKCS#8 to BIND .private and .key

PKCS#8 files can be converted to key used for DNSSEC signing in BIND. The
public key is also saved to file.

    softhsm-keyconv --tobind --in rsa.pem --name example.com. --ttl 3600 \
                    --ksk --algorithm RSASHA1-NSEC3-SHA1

Add, --pin PIN, if you the PKCS#8 file is encrypted. Use, softhsm-keyconv
--help, for more info.

The following files will be created in this example:

    Kexample.com.+007+05474.private
    Kexample.com.+007+05474.key


## Backup

A token can be backed up by issuing the command:

    sqlite3 PATH-TO-YOUR-TOKEN ".backup copy.db"

Copy the "copy.db" to a secure location. To restore the token, just copy the
file back to the system and add it to a slot in the file softhsm.conf.

If you are using SQLite3 version < 3.6.11, then you have to use the command
below. But it will not copy the "PRAGMA user_version", which is used by SoftHSM
for versioning. So you have to do that manually. In this case the version
number is 100.

    sqlite3 PATH-TO-YOUR-TOKEN .dump | sqlite3 copy.db
    sqlite3 copy.db "PRAGMA user_version = 100;"

Some attributes in the PKSC#11 API are defined as CK_ULONG, unsigned long
integer, where the length of the data depends on the architecture (32-bit,
64-bit). The attributes are stored directly in the database. The database can
thus not be moved between two systems with different architectures.
