#! /usr/bin/env python2

from subprocess import check_output
import struct

# Append a signature to the image.

# openssl dgst -sha256 -sign root_ec.pem -out zephyr.sig samples/shell/outdir/96b_carbon/zephyr.bin
# cat zephyr.sig  >> samples/shell/outdir/96b_carbon/zephyr.bin

def get_signature(path):
    """
    Using openssl (and currently some hardcoded paths), return the
    signature of the given file.
    """
    return check_output(["openssl", "dgst", "-sha256",
        "-sign", "root_ec.pem", path])

def make_padding(count, padding):
    """
    Generate a pad string of the length needed to pad count bytes of
    data to the nearest multiple of padding.  Padding must be a power
    of 2 for this to work.  This also assumes 2's complement
    arithemetic.
    """
    return '\0' * ((padding - 1) & (-count))

def sign_file(binary):
    if not binary.endswith(".bin"):
        raise Exception("Binary must end in '.bin'")

    signed = binary[:-4] + ".signed.bin"

    sig = get_signature(binary)

    with open(binary, "rb") as fd:
        payload = fd.read()
    print "Signing", binary, "to", signed
    with open(signed, "wb") as fd:
        fd.write(payload)
        # print "padding: ", len(make_padding(len(payload), 16))
        fd.write(make_padding(len(payload), 16))
        fd.write(struct.pack('<8sBBBxI', 'zSiGnata', 1, 2, 1, len(sig)))
        fd.write(sig)

if __name__ == '__main__':
    sign_file('samples/shell/outdir/96b_carbon/zephyr.bin')
    sign_file('samples/2shell/outdir/96b_carbon/zephyr.bin')
