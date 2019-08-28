.DEFAULT_GOAL := help
.PHONY: test clean

UNAME_S     ?= $(shell uname -s)
MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR  := $(dir $(MKFILE_PATH))
TOOLS_DIR   := $(MKFILE_DIR)/tools
COVERAGE ?= 0

CC       ?= gcc

OPTFLAGS ?= -O3 -g -fPIC

CFLAGS   += $(OPTFLAGS) \
            -std=gnu99 \
            -W \
            -Wall \
            -Wextra \
            -Wimplicit-function-declaration \
            -Wredundant-decls \
            -Wstrict-prototypes \
            -Wundef \
            -Wshadow \
            -Wpointer-arith \
            -Wformat \
            -Wreturn-type \
            -Wsign-compare \
            -Wmultichar \
            -Wformat-nonliteral \
            -Winit-self \
            -Wuninitialized \
            -Wformat-security \
            -Werror

ifneq ($(CHECK_PATH),)
ifeq ($(UNAME_S), Linux)
	TESTINC+=-isystem $(CHECK_PATH)/src
	TESTINC+=-isystem $(CHECK_PATH)
endif
ifeq ($(UNAME_S), Darwin)
	TESTINC+=-isystem $(CHECK_PATH)/include
endif
endif
INC += -I$(TOOLS_DIR)
INC += -I../tiny-firmware/vendor/libskycoin/include
CFLAGS += -I$(MKFILE_DIR) $(INC)
CFLAGS += -DUSE_CARDANO=0 -DUSE_CARDANO=0 -DUSE_BIP32_25519_CURVES=0 -DUSE_MONERO=0

SRCS += skycoin_crypto.c
SRCS += skycoin_signature.c
SRCS += check_digest.c
# --hide="*test_*"
SRCS += $(shell ls $(TOOLS_DIR)/*.c | grep -v test_)
SRCS += sha3.o
SRCS += blake2b.o
SRCS += groestl.o
SRCS += address.o
SRCS += aes/aes_modes.o
SRCS += aes/aescrypt.o
SRCS += aes/aeskey.o
SRCS += aes/aestab.o
#SRCS += aes/aestst.o
SRCS += ed25519-donna/curve25519-donna-32bit.o
SRCS += ed25519-donna/curve25519-donna-helpers.o
SRCS += ed25519-donna/curve25519-donna-scalarmult-base.o
SRCS += ed25519-donna/ed25519-donna-32bit-tables.o
SRCS += ed25519-donna/ed25519-donna-basepoint-table.o
SRCS += ed25519-donna/ed25519-donna-impl-base.o
SRCS += ed25519-donna/ed25519-keccak.o
SRCS += ed25519-donna/ed25519-sha3.o
SRCS += ed25519-donna/ed25519.o
SRCS += ed25519-donna/modm-donna-32bit.o

OBJS   = $(SRCS:.c=.o)

%.o: %.c %.h
	$(CC) $(CFLAGS) -o $@ -c $<

LIBS_DARWIN +=
TESTLIBS_DARWIN += -L$(CHECK_PATH)/lib -lcheck
LIBS_LINUX += -L/usr/local/lib/ -lm -lrt
TESTLIBS_LINUX += -L$(CHECK_PATH)/src -lcheck

ifeq ($(UNAME_S), Linux)
	LIBS=$(LIBS_LINUX)
	TESTLIBS=$(TESTLIBS_LINUX)
endif
ifeq ($(COVERAGE), 1)
	CFLAGS += -fprofile-arcs -ftest-coverage
	TESTLIBS+=-lgcov --coverage
endif
ifeq ($(UNAME_S), Darwin)
	LIBS=$(LIBS_DARWIN)
	TESTLIBS=$(TESTLIBS_DARWIN)
endif


all: test_skycoin_crypto

libskycoin-crypto.so: skycoin_crypto.o $(OBJS)
	$(CC) -rdynamic -shared $(CFLAGS) $(OBJS) -o libskycoin-crypto.so

libskycoin-crypto.a: skycoin_crypto.o $(OBJS)
	$(AR) rcs libskycoin-crypto.a skycoin_crypto.o $(OBJS)

libskycoin-wrapper.o: libskycoin-wrapper.c
	$(CC) -std=c99 -isystem../tiny-firmware/vendor/libskycoin/include -Itools -o libskycoin-wrapper.o -c libskycoin-wrapper.c

libskycoin-crypto-wrapper.a: libskycoin-wrapper.o libskycoin-crypto.a
	$(AR) rcs libskycoin-crypto-wrapper.a libskycoin-wrapper.o

test_skycoin_crypto.o: test_skycoin_crypto.c
	$(CC) $(CFLAGS) $(TESTINC) -o $@ -c $<

tools/test_bip32.o: tools/test_bip32.c	
	$(CC) $(CFLAGS) $(TESTINC) -o $@ -c $<

test_skycoin_crypto: test_skycoin_crypto.o tools/test_bip32.o libskycoin-crypto.so
	$(CC) test_skycoin_crypto.o $(OBJS) -L. -Wl,-rpath,$(MKFILE_DIR) -lskycoin-crypto $(LIBS) $(TESTLIBS) -o test_skycoin

test: test_skycoin_crypto ## Run test suite for Skycoin cipher library for firmware
	./test_skycoin_crypto
	./test_skycoin_crypto.py

clean: ## Delete all temporary files
	rm -f $(MKFILE_DIR)/*.o test_skycoin_crypto
	rm -f $(MKFILE_DIR)/*.so
	rm -f $(TOOLS_DIR)/*.o
	rm -f $(MKFILE_DIR)/tools/*.o
	rm -f $(MKFILE_DIR)/*.a

coverage: test_skycoin_crypto
	gcov -n -b $(SRCS) test_skycoin_crypto.c

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

