#! /bin/bash

# Start the jlink gdb server
JLinkGDBServer -if swd -device STM32F401RE -speed auto
