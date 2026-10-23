# SPDX-License-Identifier: GPL-2.0-only

always-y += $(LLVM_PLUGIN)
targets += $(LLVM_PLUGIN)
clean-files += *.so

llvm_cxxflags := $(shell $(LLVM_CONFIG) --cxxflags)
llvm_ldflags := $(shell $(LLVM_CONFIG) --ldflags)

quiet_cmd_llvm_plugin = HOSTCXX $@
      cmd_llvm_plugin = $(HOSTCXX) $(KBUILD_HOSTCXXFLAGS) $(llvm_cxxflags) \
		-fPIC -shared -o $@ $(src)/$(notdir $(@:.so=.cpp)) $(llvm_ldflags)

$(obj)/bpf_scan_ast.so: $(src)/bpf_scan_ast_metadata.h
$(obj)/bpf_context_ir.so: $(src)/bpf_context_metadata.h $(src)/bpf_scan_ast_metadata.h

$(obj)/%.so: $(src)/%.cpp FORCE
	$(call if_changed,llvm_plugin)

$(obj)/../../include/generated/llvm-plugins.h: $(addprefix $(obj)/, $(LLVM_PLUGIN)) FORCE
	$(call if_changed,touch)
always-y += ../../include/generated/llvm-plugins.h
