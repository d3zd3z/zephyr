.. _boot:

A bootloader for Zephyr
#######################

The code under ``misc/boot`` and ``samples/boot`` implement a small
bootloader for Zephyr.  This bootloader is built as an ordinary Zephyr
application.  The bootloader has the following features:

- It contain a public key, and verify a signature in the primary
  image, and will refuse to run this image if the signature
  verification fails.

- It will detect an *upgrade image* in another flash partition, and as
  long as its signature is valid, will replace the primary with this
  upgraded image.

Building the bootloader and images
----------------------------------

In order to use an image with the bootloader, it's base address must
be modified to match the *primary image* as defined in
``arch/arm/soc/.../boot_config.h``.  The following config options will
need to be modified:

- **CONFIG_SIGNATURE_HANDLER**: This adds a small header to the image
  that allows the boot loader to determine the size of the signed part
  of the image, as well as to find the signature itself.

- **CONFIG_FLASH_BASE_ADDRESS**: This should be set to be the same as
  the executable base address of the *primary* partition defined for
  this SOC.

The bootloader itself should be buildable with the default options for
the ``samples/boot``.  The sample bootloader checks for an upgrade,
and then boots the primary image, if available.

Generating the signing keys
---------------------------

The git repository for Zephyr contains a sample signing key that can
be used for development.  However, this key should not be used for
production, because the private key has been checked into a public git
repository.  To use another key, follow these instructions.

Generating an RSA key
+++++++++++++++++++++

#. Generate a signing key::

     $ openssl genrsa -out root.pem 2048

   This will generate a private key 'root.pem'.

#. Extract the public key::

     $ openssl rsa -in root.pem -pubout -out root_pub.der -outform DER -RSAPublicKey_out

#. Convert to a C file::

     $ xxd -i root_pub.der root_pub.c

   Edit ``root_pub.c`` and make both declarations ``const``.  Move
   this file into ``samples/boot/src`` to replace the key that is
   there.

Generating an ECDSA key
+++++++++++++++++++++++

ECDSA has the advantage of offering similar security with much smaller
keys.  A disadvantage is that the signature checking takes longer.
There are also a lot of common curves (including all of the curves
used in mbedTLS) that are suspected of having weakenesses.

#. To use the secp224r1 curve, generate a keypair using these
   parameters::

     $ openssl ecparam -name secp224r1 -genkey -out root_ec.pem

   The details can be viewed with::

     $ openssl ecparam -noout -in root_ec.pem -text -param_enc explicit

#. Extract the public key, and embed this key into the bootloader
   code::

     $ openssl ec -in root_ec.pem -pubout -out root_ec_pub.der \
       -outform DER
     $ xxd -i root_ec_pub.der root_ec_pub.c

   Edit the ``root_ec_pub.c`` file, adding ``const`` to both
   declarations, and move the file into ``samples/boot/src``,
   replacing the key that is there.

Signing images
--------------

Once you have either a ``root_ec.pem`` or a ``root.pem`` file to sign
with, the ``scripts/boot/sign.py`` script can be used to sign the
images.  Near the top of this file, there is an ``if True`` or similar
statement that decides between RSA and ECDSA.  Change this, if
necessary, and you can set the signed images near the end of this
file.  Each signed image takes a ``filname.bin`` file and generates a
``filename.signed.bin`` file with the signature appended.  This signed
binary file is what should be flashed into the appropriate partition.
