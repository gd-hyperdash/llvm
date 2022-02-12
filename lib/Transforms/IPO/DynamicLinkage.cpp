//===- DynamicLinkage.cpp - Dynamic linkage handler ---------------------===//
//
// See ML_LICENSE.txt for license information.
//
//===--------------------------------------------------------------------===//

#include "llvm/Transforms/IPO/DynamicLinkage.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/Transforms/Utils/MLUtils.h"

using namespace llvm;

#define DEBUG_TYPE "dynamic_linkage"

//===--------------------------------------------------------------------===//
// Globals
//===--------------------------------------------------------------------===//

static auto constexpr PAD_SIZE_ARM64 = 4u;
static auto constexpr PAD_SIZE_ARM = 2u; // arm nop is 4 but we dont care.
static auto constexpr PAD_SIZE_X = 1u;

static std::string const T_SYM("MLDynThrow");

//===--------------------------------------------------------------------===//
// Helpers
//===--------------------------------------------------------------------===//

static void ShowDebugString(StringRef S) {
  LLVM_DEBUG(llvm::dbgs() << "Dynamic Linkage Handler: " << S << '\n');
}

/// Get target arch of module.
static Triple::ArchType GetModuleArch(Module &M) {
  return Triple(M.getTargetTriple()).getArch();
}

//===--------------------------------------------------------------------===//
// Generators
//===--------------------------------------------------------------------===//

/// ARM & X, 64 & 32.
static void EmitNopAX6432N(LLVMContext &Context, IRBuilderBase &Builder,
                           unsigned N) {
  auto RetTy = Type::getVoidTy(Context);
  auto FnTy = FunctionType::get(RetTy, false);
  auto IA = InlineAsm::get(FnTy, "nop", "", true, false, InlineAsm::AD_Intel);

  for (auto i = 0u; i < N; ++i) {
    Builder.CreateCall(IA)->addAttribute(AttributeList::FunctionIndex,
                                         Attribute::NoUnwind);
  }
}

/// Emits pad instructions, N times.
static void EmitPadN(LLVMContext &Context, const Triple::ArchType Arch,
                     IRBuilderBase &Builder, unsigned N) {
  if (N) {
    switch (Arch) {
    case Triple::aarch64:
    case Triple::aarch64_be:
    case Triple::aarch64_32:
    case Triple::arm:
    case Triple::armeb:
    case Triple::x86_64:
    case Triple::x86:
      EmitNopAX6432N(Context, Builder, N);
      break;
    default:;
    }
  }
}

/// Dispatcher for target specific paddings.
static void GeneratePadding(LLVMContext &Context, const Triple::ArchType Arch,
                            IRBuilderBase &Builder) {
  unsigned N = 0;

  switch (Arch) {
  case Triple::aarch64:
  case Triple::aarch64_be:
    // movz x30, 0x7788
    // movk x30, 0x5566, lsl 16
    // movk x30, 0x3344, lsl 32
    // movk x30, 0x1122, lsl 48
    // br x30
    // 20 bytes
    N = 20 / PAD_SIZE_ARM64;
    break;
  case Triple::aarch64_32:
  case Triple::arm:
  case Triple::armeb:
    // ldr pc, [pc, #-4] (A32)
    // ldr pc, [pc] (T32)
    // 8 bytes
    N = 8 / PAD_SIZE_ARM;
    break;
  case Triple::x86_64:
    // push ldword
    // mov [rsp + 4], hdword
    // ret
    // 14 bytes
    N = 14 / PAD_SIZE_X;
    break;
  case Triple::x86:
    // jmp rel32
    // 5 bytes
    N = 5 / PAD_SIZE_X;
    break;
  default:
    N = 0;
  }

  EmitPadN(Context, Arch, Builder, N);
}

/// Emits a dummmy return instruction when possible. The generated code is not
/// supposed to be ran (program throws before reaching it) but no returns break
/// the LLVM optimizer, so we need it.
static void EmitDummyRet(IRBuilderBase &Builder, Function &D) {
  auto RetTy = D.getReturnType();

  // Handle void type.
  if (RetTy->isVoidTy()) {
    Builder.CreateRetVoid();
    return;
  }

  // Handle everything else.
  Builder.CreateRet(Constant::getNullValue(RetTy));
}

/// Generates throw function.
static Function *GetOrInsertThrow(Module &M) {
  auto &Context = M.getContext();

  // Get type.
  auto RetTy = Type::getVoidTy(Context);
  auto ParamTy = Type::getInt8PtrTy(Context);
  auto FnTy = FunctionType::get(RetTy, {ParamTy}, false);
  assert(FnTy && "Type was nullptr!");

  // Check if we already have a declaration.
  if (auto F = M.getFunction(T_SYM)) {
    if (F->getFunctionType() == FnTy) {
      return F;
    }

    // Remove incorrect declaration.
    F->eraseFromParent();
  }

  // Add fallback function.
  auto Callee = M.getOrInsertFunction(T_SYM, FnTy);
  auto Func = cast<Function>(Callee.getCallee());
  Func->setLinkage(GlobalValue::ExternalLinkage);
  Func->setCallingConv(CallingConv::C);
  Func->addAttribute(AttributeList::FunctionIndex, Attribute::Naked);

  return Func;
}

/// Generate the dynamic.
static Constant *GenerateDynamic(Module &M, const Triple::ArchType Arch,
                                 Function &D, Function &T) {
  auto &Context = M.getContext();
  IRBuilder<> Builder(Context);

  // Add symbol to module.
  auto SymPtr = Builder.CreateGlobalStringPtr(D.getName(), "", 0u, &M);

  // If the dynamic lacks a body, we generate one that throws
  // an error at runtime.
  if (D.empty()) {
    auto BB = BasicBlock::Create(Context, "", &D);
    Builder.SetInsertPoint(BB);

    // Add throw call.
    Builder.CreateCall(&T, {SymPtr});

    // Emit dummy return.
    EmitDummyRet(Builder, D);
  }

  // Add padding bytes.
  auto &Entry = D.getEntryBlock();
  Builder.SetInsertPoint(&Entry, Entry.begin());
  GeneratePadding(Context, Arch, Builder);

  return SymPtr;
}

/// Generates the record.
static Constant *GenerateRecord(Module &M, Function &D) {
  return InsertString(M, GetDynamicRecord(D));
}

/// Generates the MID.
static Constant *GenerateMID(Module &M, Function &D) {
  return InsertString(M, GetDynamicMID(D));
}

//===--------------------------------------------------------------------===//
// Main
//===--------------------------------------------------------------------===//

static bool ModuleAction(Module &M) {
  DynamicEntry Entry = {};

  // Get target arch.
  auto Arch = GetModuleArch(M);

  if (Arch == Triple::UnknownArch) {
    ShowDebugString("Could not determine target arch!");
  }

  for (auto &D : M.functions()) {
    if (!IsDynamic(D)) {
      continue;
    }

    // Get fallback.
    auto T = GetOrInsertThrow(M);

    Entry.Function = &D;
    Entry.Symbol = GenerateDynamic(M, Arch, D, *T);
    Entry.Record = GenerateRecord(M, D);
    Entry.MID = GenerateMID(M, D);

    // Make sure the dynamic isnt inlined/merged.
    D.addAttribute(AttributeList::FunctionIndex, Attribute::NoInline);

    // Append to array.
    AppendToDynamicArray(M, Entry);
  }

  return true;
}

//===--------------------------------------------------------------------===//
// Boilerplate
//===--------------------------------------------------------------------===//

char DynamicLinkageLegacy::ID = 0;

PreservedAnalyses DynamicLinkagePass::run(Module &M, ModuleAnalysisManager &) {
  return ModuleAction(M) ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

bool DynamicLinkageLegacy::runOnModule(Module &M) { return ModuleAction(M); }

Pass *llvm::createDynamicLinkageLegacyPass() {
  return new DynamicLinkageLegacy();
}