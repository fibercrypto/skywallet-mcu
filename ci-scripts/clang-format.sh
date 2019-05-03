#!/usr/bin/env bash
clang-format -assume-filename=.clang-format -i $(find ./ -type f -name *.c -o -name *.h | egrep -v "^(./tiny-firmware/protob/|./tiny-firmware/vendor/)")
