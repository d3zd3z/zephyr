target remote localhost:2331
symbol-file samples/boot/outdir/96b_carbon/zephyr.elf
# dir apps/boot/src
# dir libs/bootutil/src
# dir hw/mcu/stm/stm32f4xx/src
# b main
# b cmp_rsasig
# b bootutil_verify_sig
b mbedtls_rsa_public
# b boot_calloc
mon reset 2
