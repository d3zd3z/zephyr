#! /bin/bash

JLinkExe -device STM32F401RE -si SWD -speed auto \
	-CommanderScript flash_all.jlink
