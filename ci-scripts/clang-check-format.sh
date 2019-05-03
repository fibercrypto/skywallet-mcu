#!/usr/bin/env bash
clang-format -assume-filename=.clang-format -i $(git diff develop --name-only | grep -E "\.(c|h)$" | egrep -v "^(./tiny-firmware/protob/|./tiny-firmware/vendor/)")
clang-format -assume-filename=.clang-format -i $(git diff master --name-only | grep -E "\.(c|h)$" | egrep -v "^(./tiny-firmware/protob/|./tiny-firmware/vendor/)")
git diff --exit-code
