//===- MLUtils.cpp - ML Utils -------------------------------------------===//
//
// See ML_LICENSE.txt for license information.
//
//===--------------------------------------------------------------------===//

#include "llvm/Transforms/Utils/MLUtils.h"
#include "llvm/IR/Constants.h"

using namespace llvm;

//===--------------------------------------------------------------------===//
// Globals
//===--------------------------------------------------------------------===//

static auto constexpr DYNAMIC_OP_SIZE = 2u; // Record - MID
static auto constexpr DECORATOR_OP_SIZE = 2u; // Sym - Flags

//===--------------------------------------------------------------------===//
// Helpers
//===--------------------------------------------------------------------===//

/// Get dynamic metadata.
static MDNode *GetDynamicMD(Function &D) {
  auto MD = D.getMetadata(ml::DYNAMIC);
  if (MD) {
    assert(MD->getNumOperands() == DYNAMIC_OP_SIZE && "Invalid metadata!");
    return MD;
  }
  return nullptr;
}

/// Get decorator metadata.
static MDNode *GetDecoratorMD(Function &D) {
  auto MD = D.getMetadata(ml::DECORATOR);
  if (MD) {
    assert(MD->getNumOperands() == DECORATOR_OP_SIZE && "Invalid metadata!");
    return MD;
  }
  return nullptr;
}

/// Get decorator flags.
static std::uint64_t GetDecoratorFlags(Function &D) {
  auto MD = GetDecoratorMD(D);
  assert(MD && "No metadata!");
  return cast<ConstantInt>(
             cast<ConstantAsMetadata>(MD->getOperand(1u))->getValue())
      ->getZExtValue();
}

//===--------------------------------------------------------------------===//
// ML Utils
//===--------------------------------------------------------------------===//

Args llvm::PushArgs(IRBuilderBase &Builder) {
  Args Buffer;
  auto BB = Builder.GetInsertBlock();
  assert(BB && "No block?");
  auto F = BB->getParent();
  assert(F && "No function?");

  for (auto &A : F->args()) {
    auto P = Builder.CreateAlloca(A.getType());
    Builder.CreateStore(&A, P);
    Buffer.push_back(P);
  }

  return Buffer;
}

Args llvm::PopArgs(IRBuilderBase &Builder, const Args &Pushed) {
  Args Buffer;
  auto BB = Builder.GetInsertBlock();
  assert(BB && "No block?");
  auto F = BB->getParent();
  assert(F && "No function?");
  (void)F;

  for (auto A : Pushed) {
    auto Ty = A->getType()->getPointerElementType();
    Buffer.push_back(Builder.CreateLoad(Ty, A));
  }

  return Buffer;
}

Constant *llvm::GetFunctionAsPointer(LLVMContext &Context, Function &F) {
  return ConstantExpr::getBitCast(&F, Type::getInt8PtrTy(Context));
}

Constant *llvm::GetConstantNumber64(LLVMContext &Context,
                                    std::uint64_t const Value) {
  return ConstantInt::get(Type::getInt64Ty(Context), APInt(64u, Value));
}

Constant *llvm::InsertString(Module &M, StringRef S) {
  auto &Context = M.getContext();

  if (S.size() && !M.getGlobalVariable(S, true)) {
    IRBuilder<> Builder(Context);
    return Builder.CreateGlobalStringPtr(S, S, 0u, &M);
  }

  return ConstantPointerNull::get(Type::getInt8PtrTy(Context));
}

//===--------------------------------------------------------------------===//
// ML Dynamic Utils
//===--------------------------------------------------------------------===//

bool llvm::IsDynamic(Function &F) { return F.hasMetadata(ml::DYNAMIC); }

std::string llvm::GetDynamicRecord(Function &D) {
  auto MD = GetDynamicMD(D);
  assert(MD && "No metadata!");
  return cast<MDString>(MD->getOperand(0u))->getString().str();
}

std::string llvm::GetDynamicMID(Function &D) {
  auto MD = GetDynamicMD(D);
  assert(MD && "No metadata!");
  return cast<MDString>(MD->getOperand(1u))->getString().str();
}

void llvm::AppendToDynamicArray(Module &M, const DynamicEntry &Entry) {
  auto &Context = M.getContext();
  SmallVector<Constant *, 16> CurrentDynamics;

  auto ETy = StructType::get(Type::getInt8PtrTy(Context), /* Function */
                             Type::getInt8PtrTy(Context), /* Symbol */
                             Type::getInt8PtrTy(Context), /* Record */
                             Type::getInt8PtrTy(Context)  /* MID */
  );

  if (GlobalVariable *DynList = M.getNamedGlobal(ml::DYNAMIC_ARRAY)) {
    if (Constant *Init = DynList->getInitializer()) {
      unsigned n = Init->getNumOperands();
      CurrentDynamics.reserve(n + 1);
      for (unsigned i = 0u; i != n; ++i)
        CurrentDynamics.push_back(cast<Constant>(Init->getOperand(i)));
    }
    DynList->eraseFromParent();
  }

  Constant *CSVals[4] = {};

  CSVals[0] = GetFunctionAsPointer(Context, *Entry.Function);
  CSVals[1] = Entry.Symbol;
  CSVals[2] = Entry.Record;
  CSVals[3] = Entry.MID;

  CurrentDynamics.push_back(
      ConstantStruct::get(ETy, makeArrayRef(CSVals, ETy->getNumElements())));

  auto NewInit = ConstantArray::get(ArrayType::get(ETy, CurrentDynamics.size()),
                                    CurrentDynamics);

  (void)new GlobalVariable(M, NewInit->getType(), false,
                           GlobalValue::AppendingLinkage, NewInit,
                           ml::DYNAMIC_ARRAY);
}

//===--------------------------------------------------------------------===//
// ML Decorator Utils
//===--------------------------------------------------------------------===//

bool llvm::IsDecorator(Function &F) { return F.hasMetadata(ml::DECORATOR); }

Function *llvm::GetDecoratorBase(Module &M, Function &D) {
  auto MD = GetDecoratorMD(D);
  assert(MD && "No metadata!");
  auto Base = M.getFunction(cast<MDString>(MD->getOperand(0u))->getString());
  assert(Base && "No base?");
  return Base;
}

bool llvm::IsTailDecorator(Function &D) {
  return GetDecoratorFlags(D) & ml::flags::TAIL;
}

bool llvm::IsOptionalDecorator(Function &D) {
  return GetDecoratorFlags(D) & ml::flags::OPTIONAL;
}

bool llvm::IsLockingDecorator(Function &D) {
  return GetDecoratorFlags(D) & ml::flags::LOCKING;
}

void llvm::AppendToDecoratorArray(Module &M, const DecoratorEntry &Entry) {
  auto &Context = M.getContext();
  SmallVector<Constant *, 16> CurrentDecorators;

  auto ETy = StructType::get(Type::getInt8PtrTy(Context), /* Target */
                             Type::getInt8PtrTy(Context), /* Decorator */
                             Type::getInt64Ty(Context)    /* Flags */
  );

  if (GlobalVariable *DecoList = M.getNamedGlobal(ml::DECORATOR_ARRAY)) {
    if (Constant *Init = DecoList->getInitializer()) {
      unsigned n = Init->getNumOperands();
      CurrentDecorators.reserve(n + 1);
      for (unsigned i = 0u; i != n; ++i)
        CurrentDecorators.push_back(cast<Constant>(Init->getOperand(i)));
    }
    DecoList->eraseFromParent();
  }

  Constant *CSVals[3] = {};

  CSVals[0] = GetFunctionAsPointer(Context, *Entry.Target);
  CSVals[1] = GetFunctionAsPointer(Context, *Entry.Decorator);
  CSVals[2] = GetConstantNumber64(Context, Entry.Flags);

  CurrentDecorators.push_back(
      ConstantStruct::get(ETy, makeArrayRef(CSVals, ETy->getNumElements())));

  auto NewInit = ConstantArray::get(
      ArrayType::get(ETy, CurrentDecorators.size()), CurrentDecorators);

  (void)new GlobalVariable(M, NewInit->getType(), false,
                           GlobalValue::AppendingLinkage, NewInit,
                           ml::DECORATOR_ARRAY);
}