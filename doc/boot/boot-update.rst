Bootloader Image Update
#######################

A common requirement among IoT devices is the need to be able to do
remote firmware updating.  With the boot architecture we're describing
for Zephyr, the responsibility for downloading an updated image will
be on the running application.

In order to be able to safely upgrade, at a minimum, we need to divide
flash memory into some segments.  These segments will need to be
separately erasable and programmable (so that erasing one segment does
not affect the code in other segments).

.. list-table: Flash Segments
   :header-rows: 1

   * - Name
     - Description
   * - Boot
     - The bootloader, write protected
   * - Primary
     - Main application
   * - Upgrade
     - Upgrade location
   * - Scratch
     - Used for robust upgrade
   * - Recovery
     - Another image to recover problems

The “Boot” partition contains the bootloader described in this
document.  In order to have any semblance of security, this partition
must be write protected.

The “Primary” partition contains the main application code.  During
normal operation, the code in this partition will be executed.  The
application should be compiled to run in-place at this address.

The “Upgrade” partition has space for a second application image
intended to replace the primary image.  When an update is available,
the current running application should place the update image into
this partition.  Upon reboot, the bootloader will begin the process of
upgrading, which ultimately will result in this new image being placed
into the primary partition.

The other partitions, “Scratch” and “Recovery” are needed depending on
which solutions below are implemented for recovery.

Recovery
========

There are numerous situations that can cause a failure while
attempting to upgrade the primary image.  Because IoT devices do not
generally have user interaction, it is important that these scenarios
be minimized, and that there are possible methods of recovery
available, ideally that can be automated.

The most important failure to upgrade is caused by an untimely
powerdown of the device.  Some devices will be used in environments
where sudden power loss is more of an expected occurrence (think light
bulbs).  All of the techniques described in this document should be
implemented in such a way that untimely power loss will rarely cause
an upgrade failure.  Generally, this requires that state be tracked,
and that the bootloader be able to continue operations that were in
progress.  This also means that no important partition contents should
reside entirely within RAM.

This requirement makes both solutions below more complicated (one more
complicated than the other).

Aside from this powerdown recovery, other types of upgrade failures
are more rare:

- Upgrade of rogue images.  We prevent rogue images by requiring a
  signed chain-of-trust for any image before it will be considered for
  upgrade.

- Corrupt image upgrade.  The image signatures also has the benefit of
  detecting images that have become corrupt.

- Bad image deployment.  Despite testing, it is always possible that a
  vendor will deploy a signed image that itself malfunctions.  If this
  happens in such a way that the new image is unable to download an
  upgrade, the device can be rendered unusable.

- Hardware failure.  Flash devices age, and there are other causes of
  device failure.  This document presumes that these failures are
  difficult to predict the nature of, and therefore are not
  specifically mitigated again.

Given these failure scenarios, the most difficult, but still
understandable failure is the bad image deployment case.  The rest of
this document will discuss ways of recovering from this situation.  It
is important to understand that the other failure modes are already
addressed by other techniques (mostly image signing).

Simple Installation
===================

The simplest form of recovery is to perform none at all.  By
performing signature verification of new images, and doing the upgrade
in a power-safe manner, this protects against the first two types of
failure above.

Given sufficient device testing, this may be an acceptable solution.
As long as the upgrade process is tested extensively before being
deployed, the changes of deploying a malfunctioning image are low.

This solution also has the advantage of not requiring either a scratch
or recovery partition, allowing more space for code.  Regardless of
other solutions implemented, this option should be available (perhaps
through configuration) for situations where the vendor has deemed the
risk acceptable, and wishes for the additional flash space.

Recovery Partition
==================

Another, fairly simple, recovery technique is to have a dedicated
partition containing some kind of recovery image.  This image should
be compiled to execute in-place in the recovery partition.

The challenge with this approach is that it requires some way of
detecting if an image “works”.  Generally, this will involve some kind
of flash semaphore that must be set by the application to indicate
that it feels that it is working.  The bootloader may give the
application one chance to boot successfully, or it may give several.

The primary risk of this approach are false positives on the failure
detection.  For example, if the power fails while the application is
booting for the first time, the bootloader will be unable to
distinguish this failure from one caused by a bug in the application
code itself.

It is important that the update server be able to handle this kind of
scenario, and avoid the situation of continually attempting to install
the same image in the device.

This approach requires a recovery partition, but does not need a
scratch partition.

Boot Swapping
=============

A more complicated recovery technique involves swapping the primary
and primary partition.  This allows the old image to be put back into
the primary partition if the bootloader is able to determine that the
new image does not boot successfully.

Managing this adds significantly to the complexity of the bootloader:

- It needs a scratch partition to hold intermediate data (since
  holding it in RAM is not safe against bad powerdowns).  Depending on
  the flash layout, this scratch partition may need to be as large as
  the primary partition.  With some devices, it can be smaller, but
  with added complexity to detecting bad powerdowns.

- The bootloader needs a way to manage the state of the upgrade.  In
  addition to the swaps themselves, it must also know which image is
  the upgrade, and which is the primary (lest it simply swaps them on
  each boot).  This could be managed, for example, by having a version
  field in the image that must always be incremented.

- In addition, this has all of the same complexity of the recovery
  partition, needing to know whether a given image has booted
  successfully, and the update server needs to be able to know to stop
  giving the update the same image repeatedly.

Further Complexity
==================

It is possible to further combine these, for example trying to revert
to an previous image, and if that doesn't work, use a recovery
partition.
