#! /bin/bash

# Build the shell

source zephyr-env.sh

# make -C samples/shell BOARD=96b_carbon "$@"
make -C samples/hello_world CONFIG_FLASH_BASE_ADDRESS=0x08020000 BOARD=96b_carbon "$@"
