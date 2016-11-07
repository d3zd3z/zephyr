#! /bin/bash

# Build the shell

source zephyr-env.sh

# make -C samples/shell BOARD=96b_carbon "$@"
make -C samples/hello_world BOARD=96b_carbon "$@"
