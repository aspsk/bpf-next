// SPDX-License-Identifier: GPL-2.0-only
/* bpf_scan_ir: optimizer-last LLVM IR analysis for BPF. */

#include "llvm/Config/llvm-config.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#if __has_include("llvm/Plugins/PassPlugin.h")
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif

using namespace llvm;

namespace {

#if LLVM_VERSION_MAJOR >= 24
class BpfScanIRPass : public RequiredPassInfoMixin<BpfScanIRPass>
#else
class BpfScanIRPass : public PassInfoMixin<BpfScanIRPass>
#endif
{
public:
	PreservedAnalyses run(Module &, ModuleAnalysisManager &)
	{
		return PreservedAnalyses::all();
	}
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
	return {
		LLVM_PLUGIN_API_VERSION,
		"bpf_scan_ir",
		"1.0",
		[](PassBuilder &PB) {
			PB.registerOptimizerLastEPCallback(
				[](ModulePassManager &MPM, OptimizationLevel, auto...) {
					MPM.addPass(BpfScanIRPass());
				   }
			);
		}
	};
}
