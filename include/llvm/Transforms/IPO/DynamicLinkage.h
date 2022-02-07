//===- DynamicLinkage.h - Dynamic linkage handler ----------*- C++ -*-===//
//
// See ML_LICENSE.txt for license information.
//
//===-----------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_IPO_DYNAMICLINKAGE_H
#define LLVM_TRANSFORMS_IPO_DYNAMICLINKAGE_H

#include "llvm/IR/PassManager.h"

namespace llvm {
class Module;

class DynamicLinkagePass : public PassInfoMixin<DynamicLinkagePass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &);
};

class DynamicLinkageLegacy : public ModulePass {
public:
  static char ID;
  DynamicLinkageLegacy() : ModulePass(ID) {}

  bool runOnModule(Module &module) override;

  StringRef getPassName() const override { return "Dynamic Linkage Handler"; }
};

Pass *createDynamicLinkageLegacyPass();

} // end namespace llvm

#endif // LLVM_TRANSFORMS_IPO_DYNAMICLINKAGE_H