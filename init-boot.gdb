target remote localhost:2331
symbol-file samples/boot/outdir/96b_carbon/zephyr.elf
# dir apps/boot/src
# dir libs/bootutil/src
# dir hw/mcu/stm/stm32f4xx/src
b main
mon reset 2
