Flash programming state
=======================

Because different MCUs have different capabilities, we need to be able
to be a bit flexible in terms of how we support firmware upgrades.
There are some basic requirements needed for the bootloader

- Code must be authenticated before it is run.  This means a signature
  verification must be run on each boot before running the primary
  code.

- It is possible to update the code.  This code update should also be
  authenticated.

We also make some assumptions about the MCU:

- Code is executed in place (XIP).  Primarily, this means that the
  code has to be linked at the address it is intended to run at.  As a
  consequence, update code will have to be flashed into the "primary"
  area in order to be usable.

- There is more than 2x code space available for code migration.  The
  simplest case is that we have three regions of comparable size
  available.

- Flash is based on a NOR-type design.  Specifically, although the
  erase units will likely be large, it is possible to program
  individual bytes from an 0xFF value to another value.

Update with recovery
--------------------

This initial implementation will support what we are calling "update
with recovery".  There are two flash regions for the system image.
The "primary" image is what will normally be run, and the "update"
image will hold an image intended to update the primary image.

In addition, there is a recovery image, which is not intended to be
updated.  It should be responsible for downloading and flashing a new
"update" image, and it will be run if there are no valid images to
run.

A future possible requirement is to validate the boot of a new image.
There is some additional requirements placed on this new image, since
it will need to indicate to the bootloader, on subsequent boots, that
it considers itself healthy.

The boot algorithm is fairly simple:

- Check the "update" region for a signed image (should be built to
  run in the primary region, but flashed into the update region).
  If this image is present, and signed correctly, the bootloader
  will begin flashing this image to the "primary" region
  (overwriting it).  Once the primary has been flashed, and
  verified, the "update" region will then be erased.

- If there is no update image, the bootloader will check for a
  primary image.  If this is present, and signed correctly, it will
  run this image.

- Otherwise, the bootloader will look for a recovery image.  If the
  recovery image is present, and signed correctly, it will be run.

- If there are no images to run, we just crash.
