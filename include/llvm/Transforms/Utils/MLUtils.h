//===- Transform/Utils/MLUtils.h - ML Utils ----------------*- C++ -*-===//
//
// See ML_LICENSE.txt for license information.
//
//===-----------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_UTILS_MLUTILS_H
#define LLVM_TRANSFORMS_UTILS_MLUTILS_H

#include "llvm/IR/IRBuilder.h"

namespace llvm {

using Args = SmallVector<Value*, 4>;

struct DynamicEntry {
  Function *Function;
  Constant *Symbol;
  Constant *Record;
  Constant *MID;
};

struct DecoratorEntry {
  Function *Target;
  Function *Decorator;
  std::uint64_t Flags;
};

/// Push arguments of current function on stack.
Args PushArgs(IRBuilderBase &Builder);

/// Pop arguments from stack.
Args PopArgs(IRBuilderBase &Builder, const Args &Pushed);

/// Casts a function into i8*.
Constant *GetFunctionAsPointer(LLVMContext &Context, Function &F);

/// Returns a 64-bit constant number.
Constant *GetConstantNumber64(LLVMContext &Context, std::uint64_t const Value);

/// Inserts a global string inside a module.
Constant *InsertString(Module &M, StringRef S);

/// Check whether a function is dynamic.
bool IsDynamic(Function &F);

/// Get the record of a dynamic, or an empty string if there is none.
std::string GetDynamicRecord(Function &D);

// Get the dynamic module ID, or an empty string if there is none.
std::string GetDynamicMID(Function& D);

/// Add dynamic to global list.
void AppendToDynamicArray(Module &M, const DynamicEntry &Entry);

/// Check whether a function is a decorator.
bool IsDecorator(Function &F);

/// Return the base of a decorator.
Function *GetDecoratorBase(Module &M, Function &D);

/// Check whether a decorator is a tail.
bool IsTailDecorator(Function &D);

/// Check whether a decorator is optional.
bool IsOptionalDecorator(Function &D);

/// Check whether a decorator is locking.
bool IsLockingDecorator(Function &D);

/// Add decorator to global list.
void AppendToDecoratorArray(Module &M, const DecoratorEntry &Entry);

} // namespace llvm

#endif // LLVM_TRANSFORMS_UTILS_MLUTILS_H