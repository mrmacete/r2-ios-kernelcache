R2_PLUGIN_PATH=$(shell r2 -hh|grep LIBR_PLUGINS|awk '{print $$2}')
CFLAGS_BIN=-g -fPIC $(shell pkg-config --cflags r_bin)
LDFLAGS_BIN=-shared $(shell pkg-config --libs r_bin) -lr_syscall
LDFLAGS_EXEC=$(shell pkg-config --libs r_bin)
EXT_SO=$(shell r2 -hh|grep LIBEXT|awk '{print $$2}')
SUDO=sudo

CC_ASAN=-fsanitize=address
CC_BIN=$(CC) $(CFLAGS_BIN) $(LDFLAGS_BIN)
CC_EXEC=$(CC) $(CFLAGS_BIN) $(LDFLAGS_EXEC)

all:
	$(CC_BIN) -DR_CF_DICT_IN_LIB -o bin_kernelcache.$(EXT_SO) bin_kernelcache.c r_cf_dict.c yxml.c format/mach0/mach064.c
	$(CC_EXEC) -o cfdict-parse r_cf_dict.c yxml.c

install: all
	$(SUDO) cp -f *.$(EXT_SO) $(R2_PLUGIN_PATH)

uninstall:
	for a in *.$(EXT_SO) ; do rm -f $(R2_PLUGIN_PATH)/$$a ; done

clean:
	rm -f *.$(EXT_SO)
	rm -rf *.$(EXT_SO).dSYM
