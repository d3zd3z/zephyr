#! /bin/sh

# Append a signature to the image.

openssl dgst -sha256 -sign root.pem -out zephyr.sig samples/shell/outdir/96b_carbon/zephyr.bin
cat zephyr.sig  >> samples/shell/outdir/96b_carbon/zephyr.bin
