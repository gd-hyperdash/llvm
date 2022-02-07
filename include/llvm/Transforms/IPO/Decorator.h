//===- Decorator.h - Decorator handler ---------------------*- C++ -*-===//
//
// See ML_LICENSE.txt for license information.
//
//===-----------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_IPO_DECORATOR_H
#define LLVM_TRANSFORMS_IPO_DECORATOR_H

#include "llvm/IR/PassManager.h"

namespace llvm {
class Module;

class DecoratorPass : PassInfoMixin<DecoratorPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &);
};

class DecoratorLegacy : public ModulePass {
public:
  static char ID;
  DecoratorLegacy() : ModulePass(ID) {}

  bool runOnModule(Module &module) override;

  StringRef getPassName() const override { return "Decorator Handler"; }
};

Pass *createDecoratorLegacyPass();

} // namespace llvm

#endif // LLVM_TRANSFORMS_IPO_DECORATOR_H