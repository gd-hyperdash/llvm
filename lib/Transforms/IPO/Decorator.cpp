//===- Decorator.cpp - Decorator handler --------------------------------===//
//
// See ML_LICENSE.txt for license information.
//
//===--------------------------------------------------------------------===//

#include "llvm/Transforms/IPO/Decorator.h"
#include "llvm/Support/MD5.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/MLUtils.h"

using namespace llvm;

#define DEBUG_TYPE "decorator"

//===--------------------------------------------------------------------===//
// Types
//===--------------------------------------------------------------------===//

using Traps = llvm::SmallVector<IntrinsicInst *, 4u>;
using Ends = llvm::SmallVector<Instruction *, 4u>;

//===--------------------------------------------------------------------===//
// Globals
//===--------------------------------------------------------------------===//

static std::string const GET_T_SYM("MLDecoGetTrampoline");
static std::string const GET_FD_SYM("MLDecoGetFirst");
static std::string const GET_ND_SYM("MLDecoGetNext");

//===--------------------------------------------------------------------===//
// TailTypeBuilder
//===--------------------------------------------------------------------===//

class TailTypeBuilder {
  friend class TailCallBuilder;

  struct RetArg {
    Type *Ty = nullptr;
    Argument *Arg = nullptr;

    RetArg() = default;
  };

protected:
  SmallVector<Argument*, 2> Args;
  RetArg Ret;

   void DumpRet(Function &H) {
    auto T = H.getReturnType();

    if (T->isVoidTy()) {
      for (auto i = 0u; i < H.arg_size(); ++i) {
        auto A = H.getArg(i);
        if (A->hasStructRetAttr()) {
          Ret.Ty = A->getType();
          Ret.Arg = A;
          return;
        }
      }
    }

    Ret.Ty = T;
  }

  void Setup(Function &H, std::size_t const ArgCount) {
    for (auto i = 0u; Args.size() < ArgCount && i < H.arg_size(); ++i) {
      auto A = H.getArg(i);

      if (!A->hasStructRetAttr()) {
        Args.push_back(A);
      }
    }

    DumpRet(H);
  }

public:
  TailTypeBuilder(Function &H, std::size_t const ArgCount) {
    Setup(H, ArgCount);
  }

  FunctionType *Create(LLVMContext &Context) {
    SmallVector<Type *, 2> ArgsTy;

    for (auto A : Args) {
      ArgsTy.push_back(A->getType());
    }

    if (!Ret.Ty->isVoidTy()) {
      ArgsTy.push_back(Ret.Arg ? Ret.Ty : Ret.Ty->getPointerTo());
    }

    return FunctionType::get(Type::getVoidTy(Context), ArgsTy, false);
  }
};

//===--------------------------------------------------------------------===//
// TailCallBuilder
//===--------------------------------------------------------------------===//

class TailCallBuilder {
  IRBuilderBase &Builder;
  TailTypeBuilder &Type;
  Args ArgsV;

  void Setup(Value *RetVal) {
    for (auto A : Type.Args) {
      ArgsV.push_back(Builder.CreateAlloca(A->getType()));
      Builder.CreateStore(A, ArgsV.back());
    }

    if (!Type.Ret.Ty->isVoidTy()) {
      if (Type.Ret.Arg) {
        ArgsV.push_back(Type.Ret.Arg);
      } else {
        ArgsV.push_back(Builder.CreateAlloca(Type.Ret.Ty));
        Builder.CreateStore(RetVal, ArgsV.back(), true);
      }
    }
  }

public:
  TailCallBuilder(IRBuilderBase &IRB, TailTypeBuilder &T, Value *RetVal)
      : Builder(IRB), Type(T) {
    Setup(RetVal);
  }

  Args GetArgs() {
    auto Args = ArgsV;

    if (!Type.Ret.Ty->isVoidTy()) {
      Args.pop_back();
    }

    Args = PopArgs(Builder, Args);

    if (!Type.Ret.Ty->isVoidTy()) {
      Args.push_back(ArgsV.back());
    }

    return Args;
  }
};

//===--------------------------------------------------------------------===//
// Helpers
//===--------------------------------------------------------------------===//

static void ShowDebugString(StringRef S) {
  LLVM_DEBUG(llvm::dbgs() << "Decorator Handler: " << S << '\n');
}

static std::string GetDispatcherName(Module &M, Function &B) {
  MD5 Hash;
  MD5::MD5Result Ret;

  Hash.update(M.getName());
  Hash.update(B.getName());

  Hash.final(Ret);
  return "ml_dispatcher_" + Ret.digest().str().str();
}

static std::string GetDecoratorSignalerName(Module &M, Function &D,
                                            Function &B) {
  MD5 Hash;
  MD5::MD5Result Ret;

  Hash.update(M.getName());
  Hash.update(D.getName());
  Hash.update(B.getName());

  Hash.final(Ret);
  return "ml_decosig_" + Ret.digest().str().str();
}

static std::string GetTailSignalerName(Module &M, Function &T, Function &B) {
  MD5 Hash;
  MD5::MD5Result Ret;

  Hash.update(M.getName());
  Hash.update(T.getName());
  Hash.update(B.getName());

  Hash.final(Ret);
  return "ml_tailsig_" + Ret.digest().str().str();
}

static std::string GetTrampolineName(Module &M, Function &B) {
  MD5 Hash;
  MD5::MD5Result Ret;

  Hash.update(M.getName());
  Hash.update(B.getName());

  Hash.final(Ret);
  return "ml_trampoline_" + Ret.digest().str().str();
}

static Ends FindEnds(Function &F) {
  Instruction *Last = nullptr;
  Ends Ends = {};
  Traps Traps = {};

  for (auto &BB : F) {
    for (auto &Inst : BB) {
      // Handle unreachable.
      if (auto Undef = dyn_cast<UnreachableInst>(&Inst)) {
        Ends.push_back(Undef);
        // Handle possible trap.
        if (auto Intr = dyn_cast_or_null<IntrinsicInst>(Last)) {
          if (Intr->getIntrinsicID() == Intrinsic::trap) {
            Traps.push_back(Intr);
          }
        }
      }
      // Hndle invalid rets.
      else if (auto Ret = dyn_cast<ReturnInst>(&Inst)) {
        Ends.push_back(Ret);
      }

      Last = &Inst;
    }
  }

  // Remove traps.
  for (auto T : Traps) {
    T->eraseFromParent();
  }

  return Ends;
}

static void ReplaceBaseCalls(Function &F, Function &B, Function &T) {
  auto BTy = B.getFunctionType();

  for (auto &BB : F) {
    for (auto &Inst : BB) {
      if (auto Call = dyn_cast<CallInst>(&Inst)) {
        auto Called = Call->getCalledFunction();
        if (Called && Called->getName() == B.getName()) {
          Call->setCalledFunction(BTy, &T);
        }
      }
    }
  }
}

//===--------------------------------------------------------------------===//
// API
//===--------------------------------------------------------------------===//

static FunctionType *GetAPIType(LLVMContext &Context, StringRef Name) {
  auto PtrTy = Type::getInt8PtrTy(Context);
  auto FlagsTy = Type::getInt64Ty(Context);
  auto GetOneTy = FunctionType::get(PtrTy, {PtrTy, FlagsTy}, false);
  auto GetTwoTy = FunctionType::get(PtrTy, {PtrTy, PtrTy, FlagsTy}, false);

  if (Name == GET_T_SYM) {
    // void* MLDecoGetTrampoline(void* target, uint64_t flags);
    return GetOneTy;
  }

  if (Name == GET_FD_SYM) {
    // void* MLDecoGetFirst(void* target, uint64_t flags);
    return GetOneTy;
  }

  if (Name == GET_ND_SYM) {
    // void* MLDecoGetNext(void* target, void* callback, uint64_t flags);
    return GetTwoTy;
  }

  return nullptr;
}

static Function* GetOrInsertAPI(Module& M, StringRef Name) {
  auto &Context = M.getContext();
  auto Ty = GetAPIType(Context, Name);
  assert(Ty && "Type was nullptr!");

  // Check if we already have a declaration.
  if (auto F = M.getFunction(Name)) {
    if (F->getFunctionType() == Ty) {
      return F;
    }

    // Remove incorrect declaration.
    F->eraseFromParent();
  }

  // Add API.
  auto Callee = M.getOrInsertFunction(Name, Ty);
  auto Func = cast<Function>(Callee.getCallee());
  Func->setLinkage(GlobalValue::ExternalLinkage);
  Func->setCallingConv(CallingConv::C);

  return Func;
}

//===--------------------------------------------------------------------===//
// Generators
//===--------------------------------------------------------------------===//

static void GenerateDispatcher(Module &M, Function &B,
                   std::uint64_t const Flags, std::size_t const TailArgCount) {
  SmallVector<Type *, 1> TAL;
  DecoratorEntry ListEntry = {};
  auto &Context = M.getContext();
  auto BTy = B.getFunctionType();
  auto FDAPI = GetOrInsertAPI(M, GET_FD_SYM);
  auto Name = GetDispatcherName(M, B);
  IRBuilder<> Builder(Context);

  // Avoid generating the same dispatcher multiple times.
  if (M.getFunction(Name)) {
    return;
  }

  // Add dispatcher to module.
  auto Callee = M.getOrInsertFunction(Name, BTy);
  auto H = cast<Function>(Callee.getCallee());

  // Add body.
  auto EntryBlock = BasicBlock::Create(Context, "entry", H);
  auto TailBlock = BasicBlock::Create(Context, "tail.block", H);
  auto ReturnBlock = BasicBlock::Create(Context, "return", H);
  Builder.SetInsertPoint(EntryBlock);

  // Save possible args.
  auto Pushed = PushArgs(Builder);

  // Add deco getter call.
  auto DecoFlags = ml::flags::NONE;

  if (Flags & ml::flags::DYNAMIC_TARGET) {
    DecoFlags |= ml::flags::DYNAMIC_TARGET;
  }

  auto BPtr = GetFunctionAsPointer(Context, B);
  auto APIF = GetConstantNumber64(Context, DecoFlags);
  auto First = Builder.CreateCall(FDAPI->getFunctionType(), FDAPI, {BPtr, APIF});

  // Call first decorator.
  auto Cast = Builder.CreateBitCast(First, BTy->getPointerTo());
  Value *Ret = Builder.CreateCall(BTy, Cast, PopArgs(Builder, Pushed));

  // Add tail getter call.
  APIF = GetConstantNumber64(Context, DecoFlags | ml::flags::TAIL);
  auto NullPtr = ConstantPointerNull::get(Builder.getInt8PtrTy());
  auto FirstTail = Builder.CreateCall(FDAPI->getFunctionType(), FDAPI, {BPtr, APIF});
  auto Cond = Builder.CreateCmp(llvm::CmpInst::ICMP_NE, FirstTail, NullPtr);
  Builder.CreateCondBr(Cond, TailBlock, ReturnBlock);

  // Prepare tail call.
  TailTypeBuilder TTBuilder(*H, TailArgCount);
  auto TTy = TTBuilder.Create(Context);
  Builder.SetInsertPoint(TailBlock);
  Cast = Builder.CreateBitCast(FirstTail, TTy->getPointerTo());

  // Build tail call.
  TailCallBuilder TCBuilder(Builder, TTBuilder, Ret);
  Builder.CreateCall(TTy, Cast, TCBuilder.GetArgs());
  Builder.CreateBr(ReturnBlock);

  // Add return.
  Builder.SetInsertPoint(ReturnBlock);
  if (BTy->getReturnType()->isVoidTy()) {
    Builder.CreateRetVoid();
  } else {
    Builder.CreateRet(Ret);
  }

  // Append to decorator list.
  ListEntry.Target = &B;
  ListEntry.Decorator = H;
  ListEntry.Flags |= ml::flags::DISPATCHER;

  if (Flags & ml::flags::DYNAMIC_TARGET) {
    ListEntry.Flags |= ml::flags::DYNAMIC_TARGET;
  }

  AppendToDecoratorArray(M, ListEntry);
}

static Function *GenerateDecoratorSignaler(Module &M,
                                           const DecoratorEntry &Entry) {
  auto &D = *Entry.Decorator;
  auto &B = *Entry.Target;
  auto Flags = Entry.Flags;
  auto &Context = M.getContext();
  auto NDAPI = GetOrInsertAPI(M, GET_ND_SYM);
  auto DTy = D.getFunctionType();
  auto Name = GetDecoratorSignalerName(M, D, B);
  IRBuilder<> Builder(Context);

  // Avoid generating the same signaler multiple times.
  if (auto F = M.getFunction(Name)) {
    return F;
  }

  // Add signaler to module.
  auto Callee = M.getOrInsertFunction(Name, DTy);
  auto S = cast<Function>(Callee.getCallee());

  // Add body.
  auto Body = BasicBlock::Create(Context, "entry", S);
  Builder.SetInsertPoint(Body);

  // Save possible args.
  auto Pushed = PushArgs(Builder);

  // Add deco getter call.
  auto DecoFlags = ml::flags::NONE;

  if (Flags & ml::flags::DYNAMIC_TARGET) {
    DecoFlags |= ml::flags::DYNAMIC_TARGET;
  }

  auto BPtr = GetFunctionAsPointer(Context, B);
  auto DPtr = GetFunctionAsPointer(Context, D);
  auto APIF = GetConstantNumber64(Context, DecoFlags);
  auto Next =
      Builder.CreateCall(NDAPI->getFunctionType(), NDAPI, {BPtr, DPtr, APIF});

  // Call next decorator.
  auto Cast = Builder.CreateBitCast(Next, DTy->getPointerTo());
  Value *Ret = Builder.CreateCall(DTy, Cast, PopArgs(Builder, Pushed));

  // Add return.
  if (DTy->getReturnType()->isVoidTy()) {
    Builder.CreateRetVoid();
  } else {
    Builder.CreateRet(Ret);
  }

  // Add attributes.
  S->addAttribute(AttributeList::FunctionIndex, Attribute::AlwaysInline);

  return S;
}

static Function *GenerateTailSignaler(Module &M, const DecoratorEntry &Entry) {
  auto &T = *Entry.Decorator;
  auto &B = *Entry.Target;
  auto Flags = Entry.Flags;
  auto &Context = M.getContext();
  auto NDAPI = GetOrInsertAPI(M, GET_ND_SYM);
  auto TTy = T.getFunctionType();
  auto Name = GetTailSignalerName(M, T, B);
  IRBuilder<> Builder(Context);

  // Avoid generating the same signaler multiple times.
  if (auto F = M.getFunction(Name)) {
    return F;
  }

  // Add signaler to module.
  auto Callee = M.getOrInsertFunction(Name, TTy);
  auto S = cast<Function>(Callee.getCallee());

  // Add body.
  auto EntryBlock = BasicBlock::Create(Context, "entry", S);
  auto TailBlock = BasicBlock::Create(Context, "tail.block", S);
  auto ReturnBlock = BasicBlock::Create(Context, "return", S);
  Builder.SetInsertPoint(EntryBlock);

  // Add tail getter call.
  auto DecoFlags = ml::flags::TAIL;

  if (Flags & ml::flags::DYNAMIC_TARGET) {
    DecoFlags |= ml::flags::DYNAMIC_TARGET;
  }

  auto BPtr = GetFunctionAsPointer(Context, B);
  auto TPtr = GetFunctionAsPointer(Context, T);
  auto APIF = GetConstantNumber64(Context, DecoFlags);
  auto Next =
      Builder.CreateCall(NDAPI->getFunctionType(), NDAPI, {BPtr, TPtr, APIF});
  auto NullPtr = ConstantPointerNull::get(Builder.getInt8PtrTy());
  auto Cond = Builder.CreateCmp(llvm::CmpInst::ICMP_NE, Next, NullPtr);
  Builder.CreateCondBr(Cond, TailBlock, ReturnBlock);

  // Call next tail.
  Builder.SetInsertPoint(TailBlock);
  auto Pushed = PushArgs(Builder);
  auto Cast = Builder.CreateBitCast(Next, TTy->getPointerTo());
  Builder.CreateCall(TTy, Cast, PopArgs(Builder, Pushed));
  Builder.CreateBr(ReturnBlock);

  // Add return.
  Builder.SetInsertPoint(ReturnBlock);
  Builder.CreateRetVoid();

  // Add attributes.
  S->addAttribute(AttributeList::FunctionIndex, Attribute::AlwaysInline);

  return S;
}

static Function *GenerateTrampoline(Module &M, const DecoratorEntry &Entry) {
  auto &B = *Entry.Target;
  auto Flags = Entry.Flags;
  auto &Context = M.getContext();
  auto TAPI = GetOrInsertAPI(M, GET_T_SYM);
  auto TTy = B.getFunctionType();
  auto Name = GetTrampolineName(M, B);
  IRBuilder<> Builder(Context);

  // Avoid generating the same trampoline multiple times.
  if (auto F = M.getFunction(Name)) {
    return F;
  }

  // Add trampoline to module.
  auto Callee = M.getOrInsertFunction(Name, TTy);
  auto W = cast<Function>(Callee.getCallee());

  // Add body.
  auto Body = BasicBlock::Create(Context, "entry", W);
  Builder.SetInsertPoint(Body);

  // Save possible args.
  auto Pushed = PushArgs(Builder);

  // Add trampoline getter call.
  auto BPtr = GetFunctionAsPointer(Context, B);
  auto APIF = GetConstantNumber64(Context, Flags & ml::flags::DYNAMIC_TARGET);
  auto T = Builder.CreateCall(TAPI->getFunctionType(), TAPI, {BPtr, APIF});

  // Call trampoline.
  auto Cast = Builder.CreateBitCast(T, TTy->getPointerTo());
  Value *Ret = Builder.CreateCall(TTy, Cast, PopArgs(Builder, Pushed));

  // Add return.
  if (TTy->getReturnType()->isVoidTy()) {
    Builder.CreateRetVoid();
  } else {
    Builder.CreateRet(Ret);
  }

  // Add attributes.
  W->addAttribute(AttributeList::FunctionIndex, Attribute::AlwaysInline);

  return W;
}

//===--------------------------------------------------------------------===//
// Handlers
//===--------------------------------------------------------------------===//

static void HandleDecorator(Module &M, const DecoratorEntry &Entry) {
  auto &Context = M.getContext();
  IRBuilder<> Builder(Context);

  // Get ends.
  auto Ends = FindEnds(*Entry.Decorator);

  // Generate signaler code.
  auto S = GenerateDecoratorSignaler(M, Entry);
  auto STy = S->getFunctionType();

  // Add new block.
  auto SigBlock = BasicBlock::Create(Context, "sig.block", Entry.Decorator);
  Builder.SetInsertPoint(SigBlock);

  // Add call to signaler.
  auto Pushed = PushArgs(Builder);
  auto Ret = Builder.CreateCall(STy, S, PopArgs(Builder, Pushed));

  if (STy->getReturnType()->isVoidTy()) {
    Builder.CreateRetVoid();
  } else {
    Builder.CreateRet(Ret);
  }

  // Replace ends.
  for (auto Inst : Ends) {
    auto Br = BranchInst::Create(SigBlock);
    ReplaceInstWithInst(Inst, Br);
  }
}

static void HandleTail(Module &M, const DecoratorEntry &Entry) {
  auto &Context = M.getContext();
  IRBuilder<> Builder(Context);

  // Get ends.
  auto Ends = FindEnds(*Entry.Decorator);

  // Generate signaler code.
  auto S = GenerateTailSignaler(M, Entry);

  // Add new block.
  auto SigBlock = BasicBlock::Create(Context, "sig.block", Entry.Decorator);
  Builder.SetInsertPoint(SigBlock);

  // Add call to signaler.
  auto Pushed = PushArgs(Builder);
  Builder.CreateCall(S->getFunctionType(), S, PopArgs(Builder, Pushed));
  Builder.CreateRetVoid();

  // Replace ends.
  for (auto Inst : Ends) {
    auto Br = BranchInst::Create(SigBlock);
    ReplaceInstWithInst(Inst, Br);
  }
}

//===--------------------------------------------------------------------===//
// Main
//===--------------------------------------------------------------------===//

static bool ModuleAction(Module &M) {
  DecoratorEntry Entry = {};

  for (auto &D : M) {
    if (!IsDecorator(D)) {
      continue;
    }

    Entry.Target = GetDecoratorBase(M, D);
    Entry.Decorator = &D;
    Entry.Flags = ml::flags::NONE;

    // Set flags.
    if (IsTailDecorator(D)) {
      Entry.Flags |= ml::flags::TAIL;
    }

    if (IsOptionalDecorator(D)) {
      Entry.Flags |= ml::flags::OPTIONAL;
    }

    if (IsLockingDecorator(D)) {
      Entry.Flags |= ml::flags::LOCKING;
    }

    if (IsDynamic(*Entry.Target)) {
      Entry.Flags |= ml::flags::DYNAMIC_TARGET;
    }

    // Handle non-locking decorators.
    if (!(Entry.Flags & ml::flags::LOCKING)) {
      if (Entry.Flags & ml::flags::TAIL) {
        HandleTail(M, Entry);
      } else {
        HandleDecorator(M, Entry);
      }
    }

    // Handle base calls.
    auto T = GenerateTrampoline(M, Entry);
    ReplaceBaseCalls(*Entry.Decorator, *Entry.Target, *T);

    // Insert dispatcher.
    GenerateDispatcher(M, *Entry.Target, Entry.Flags,
                       GetTailArgCount(*Entry.Decorator));

    // Append to decorator list.
    AppendToDecoratorArray(M, Entry);
  }

  return true;
}

//===--------------------------------------------------------------------===//
// Boilerplate
//===--------------------------------------------------------------------===//

char DecoratorLegacy::ID = 0;

PreservedAnalyses DecoratorPass::run(Module &M, ModuleAnalysisManager &) {
  return ModuleAction(M) ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

bool DecoratorLegacy::runOnModule(Module &M) {
  return ModuleAction(M);
}

Pass *llvm::createDecoratorLegacyPass() { return new DecoratorLegacy(); }