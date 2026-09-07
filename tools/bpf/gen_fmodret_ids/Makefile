# SPDX-License-Identifier: GPL-2.0-only

include ../../scripts/Makefile.include
include ../../scripts/Makefile.arch

HOSTPKG_CONFIG ?= pkg-config

srctree := $(abspath $(CURDIR)/../../../)

OUTPUT ?= $(srctree)/tools/bpf/gen_fmodret_ids/
OUTPUT := $(abspath $(OUTPUT))/

RESOLVE_OUTPUT := $(abspath $(OUTPUT)/../resolve_btfids)/
RESOLVE_BTFIDS := $(RESOLVE_OUTPUT)resolve_btfids
BPFOBJ := $(RESOLVE_OUTPUT)libbpf/libbpf.a
SUBCMDOBJ := $(RESOLVE_OUTPUT)libsubcmd/libsubcmd.a
STRERROR_OBJ := $(RESOLVE_OUTPUT)str_error_r.o
LIBBPF_INCLUDE := $(RESOLVE_OUTPUT)libbpf/include

BINARY := $(OUTPUT)gen_fmodret_ids
BINARY_IN := $(BINARY)-in.o

LIBELF_FLAGS := $(shell $(HOSTPKG_CONFIG) libelf --cflags 2>/dev/null)
LIBELF_LIBS := $(shell $(HOSTPKG_CONFIG) libelf --libs 2>/dev/null || echo -lelf)
ZLIB_LIBS := $(shell $(HOSTPKG_CONFIG) zlib --libs 2>/dev/null || echo -lz)

HOSTCFLAGS_gen_fmodret_ids := $(KBUILD_HOSTCFLAGS) -g \
	-I$(srctree)/tools/include \
	-I$(srctree)/tools/include/uapi \
	-I$(LIBBPF_INCLUDE) \
	-I$(srctree)/tools/lib \
	$(LIBELF_FLAGS) \
	-Wall -Werror

all: $(BINARY)

prepare: $(BPFOBJ) $(SUBCMDOBJ) $(STRERROR_OBJ)

$(OUTPUT):
	$(Q)mkdir -p $@

$(RESOLVE_OUTPUT):
	$(Q)mkdir -p $@

$(RESOLVE_BTFIDS): | $(RESOLVE_OUTPUT)
	$(Q)$(MAKE) -sC $(srctree)/tools/bpf/resolve_btfids O=$(RESOLVE_OUTPUT)

$(BPFOBJ) $(SUBCMDOBJ) $(STRERROR_OBJ): $(RESOLVE_BTFIDS)

export srctree OUTPUT HOSTCFLAGS_gen_fmodret_ids Q HOSTCC HOSTLD HOSTAR
include $(srctree)/tools/build/Makefile.include

$(BINARY_IN): fixdep FORCE prepare | $(OUTPUT)
	$(Q)$(MAKE) $(build)=gen_fmodret_ids

$(BINARY): $(BPFOBJ) $(SUBCMDOBJ) $(STRERROR_OBJ) $(BINARY_IN)
	$(Q)$(HOSTCC) $(KBUILD_HOSTLDFLAGS) -o $@ $(BINARY_IN) \
		$(KBUILD_HOSTLDLIBS) $(BPFOBJ) $(SUBCMDOBJ) \
		$(STRERROR_OBJ) $(LIBELF_LIBS) $(ZLIB_LIBS)

clean:
	$(Q)$(RM) -f $(BINARY) $(BINARY_IN) $(OUTPUT)/*.o \
		$(OUTPUT)/.*.o.cmd $(OUTPUT)/.*.o.d
	$(Q)$(MAKE) -C $(srctree)/tools/build clean

.PHONY: all clean FORCE prepare

FORCE:
