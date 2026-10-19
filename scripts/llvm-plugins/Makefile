# SPDX-License-Identifier: GPL-2.0-only

always-y += fmodret_candidates.so
targets += fmodret_candidates.so
clean-files += *.so

llvm_cxxflags := $(shell $(LLVM_CONFIG) --cxxflags)
llvm_ldflags := $(shell $(LLVM_CONFIG) --ldflags --libs core analysis passes support --system-libs)

quiet_cmd_llvm_plugin = HOSTCXX $@
      cmd_llvm_plugin = $(HOSTCXX) $(KBUILD_HOSTCXXFLAGS) $(llvm_cxxflags) \
		-fPIC -shared -o $@ $< $(llvm_ldflags)

$(obj)/fmodret_candidates.so: $(src)/fmodret_candidates.cpp FORCE
	$(call if_changed,llvm_plugin)

$(obj)/../../include/generated/llvm-plugins.h: $(obj)/fmodret_candidates.so FORCE
	$(call if_changed,touch)
always-y += ../../include/generated/llvm-plugins.h
