; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -S -early-cse -earlycse-debug-hash | FileCheck %s --check-prefix=CHECK-NOMEMSSA
; RUN: opt < %s -S -basic-aa -early-cse-memssa | FileCheck %s
; RUN: opt < %s -S -passes='early-cse' | FileCheck %s --check-prefix=CHECK-NOMEMSSA
; RUN: opt < %s -S -aa-pipeline=basic-aa -passes='early-cse<memssa>' | FileCheck %s

@G1 = global i32 zeroinitializer
@G2 = global i32 zeroinitializer
@G3 = global i32 zeroinitializer

;; Simple load value numbering across non-clobbering store.
define i32 @test1() {
; CHECK-NOMEMSSA-LABEL: @test1(
; CHECK-NOMEMSSA-NEXT:    [[V1:%.*]] = load i32, i32* @G1, align 4
; CHECK-NOMEMSSA-NEXT:    store i32 0, i32* @G2, align 4
; CHECK-NOMEMSSA-NEXT:    [[V2:%.*]] = load i32, i32* @G1, align 4
; CHECK-NOMEMSSA-NEXT:    [[DIFF:%.*]] = sub i32 [[V1]], [[V2]]
; CHECK-NOMEMSSA-NEXT:    ret i32 [[DIFF]]
;
; CHECK-LABEL: @test1(
; CHECK-NEXT:    [[V1:%.*]] = load i32, i32* @G1, align 4
; CHECK-NEXT:    store i32 0, i32* @G2, align 4
; CHECK-NEXT:    ret i32 0
;
  %V1 = load i32, i32* @G1
  store i32 0, i32* @G2
  %V2 = load i32, i32* @G1
  %Diff = sub i32 %V1, %V2
  ret i32 %Diff
}

;; Simple dead store elimination across non-clobbering store.
define void @test2() {
; CHECK-NOMEMSSA-LABEL: @test2(
; CHECK-NOMEMSSA-NEXT:  entry:
; CHECK-NOMEMSSA-NEXT:    [[V1:%.*]] = load i32, i32* @G1, align 4
; CHECK-NOMEMSSA-NEXT:    store i32 0, i32* @G2, align 4
; CHECK-NOMEMSSA-NEXT:    store i32 [[V1]], i32* @G1, align 4
; CHECK-NOMEMSSA-NEXT:    ret void
;
; CHECK-LABEL: @test2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[V1:%.*]] = load i32, i32* @G1, align 4
; CHECK-NEXT:    store i32 0, i32* @G2, align 4
; CHECK-NEXT:    ret void
;
entry:
  %V1 = load i32, i32* @G1
  store i32 0, i32* @G2
  store i32 %V1, i32* @G1
  ret void
}

;; Check that memoryphi optimization happens during EarlyCSE, enabling
;; more load CSE opportunities.
define void @test_memphiopt(i1 %c, i32* %p) {
; CHECK-NOMEMSSA-LABEL: @test_memphiopt(
; CHECK-NOMEMSSA-NEXT:  entry:
; CHECK-NOMEMSSA-NEXT:    [[V1:%.*]] = load i32, i32* @G1, align 4
; CHECK-NOMEMSSA-NEXT:    br i1 [[C:%.*]], label [[THEN:%.*]], label [[END:%.*]]
; CHECK-NOMEMSSA:       then:
; CHECK-NOMEMSSA-NEXT:    [[PV:%.*]] = load i32, i32* [[P:%.*]], align 4
; CHECK-NOMEMSSA-NEXT:    br label [[END]]
; CHECK-NOMEMSSA:       end:
; CHECK-NOMEMSSA-NEXT:    [[V2:%.*]] = load i32, i32* @G1, align 4
; CHECK-NOMEMSSA-NEXT:    [[SUM:%.*]] = add i32 [[V1]], [[V2]]
; CHECK-NOMEMSSA-NEXT:    store i32 [[SUM]], i32* @G2, align 4
; CHECK-NOMEMSSA-NEXT:    ret void
;
; CHECK-LABEL: @test_memphiopt(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[V1:%.*]] = load i32, i32* @G1, align 4
; CHECK-NEXT:    br i1 [[C:%.*]], label [[THEN:%.*]], label [[END:%.*]]
; CHECK:       then:
; CHECK-NEXT:    [[PV:%.*]] = load i32, i32* [[P:%.*]], align 4
; CHECK-NEXT:    br label [[END]]
; CHECK:       end:
; CHECK-NEXT:    [[SUM:%.*]] = add i32 [[V1]], [[V1]]
; CHECK-NEXT:    store i32 [[SUM]], i32* @G2, align 4
; CHECK-NEXT:    ret void
;
entry:
  %v1 = load i32, i32* @G1
  br i1 %c, label %then, label %end

then:
  %pv = load i32, i32* %p
  store i32 %pv, i32* %p
  br label %end

end:
  %v2 = load i32, i32* @G1
  %sum = add i32 %v1, %v2
  store i32 %sum, i32* @G2
  ret void
}


;; Check that MemoryPhi optimization and MemoryUse re-optimization
;; happens during EarlyCSE, enabling more load CSE opportunities.
define void @test_memphiopt2(i1 %c, i32* %p) {
; CHECK-NOMEMSSA-LABEL: @test_memphiopt2(
; CHECK-NOMEMSSA-NEXT:  entry:
; CHECK-NOMEMSSA-NEXT:    [[V1:%.*]] = load i32, i32* @G1, align 4
; CHECK-NOMEMSSA-NEXT:    store i32 [[V1]], i32* @G2, align 4
; CHECK-NOMEMSSA-NEXT:    br i1 [[C:%.*]], label [[THEN:%.*]], label [[END:%.*]]
; CHECK-NOMEMSSA:       then:
; CHECK-NOMEMSSA-NEXT:    [[PV:%.*]] = load i32, i32* [[P:%.*]], align 4
; CHECK-NOMEMSSA-NEXT:    br label [[END]]
; CHECK-NOMEMSSA:       end:
; CHECK-NOMEMSSA-NEXT:    [[V2:%.*]] = load i32, i32* @G1, align 4
; CHECK-NOMEMSSA-NEXT:    store i32 [[V2]], i32* @G3, align 4
; CHECK-NOMEMSSA-NEXT:    ret void
;
; CHECK-LABEL: @test_memphiopt2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[V1:%.*]] = load i32, i32* @G1, align 4
; CHECK-NEXT:    store i32 [[V1]], i32* @G2, align 4
; CHECK-NEXT:    br i1 [[C:%.*]], label [[THEN:%.*]], label [[END:%.*]]
; CHECK:       then:
; CHECK-NEXT:    [[PV:%.*]] = load i32, i32* [[P:%.*]], align 4
; CHECK-NEXT:    br label [[END]]
; CHECK:       end:
; CHECK-NEXT:    store i32 [[V1]], i32* @G3, align 4
; CHECK-NEXT:    ret void
;
entry:
  %v1 = load i32, i32* @G1
  store i32 %v1, i32* @G2
  br i1 %c, label %then, label %end

then:
  %pv = load i32, i32* %p
  store i32 %pv, i32* %p
  br label %end

end:
  %v2 = load i32, i32* @G1
  store i32 %v2, i32* @G3
  ret void
}

;; Check that we respect lifetime.start/lifetime.end intrinsics when deleting
;; stores that, without the lifetime calls, would be writebacks.
define void @test_writeback_lifetimes(i32* %p) {
; CHECK-NOMEMSSA-LABEL: @test_writeback_lifetimes(
; CHECK-NOMEMSSA-NEXT:  entry:
; CHECK-NOMEMSSA-NEXT:    [[Q:%.*]] = getelementptr i32, i32* [[P:%.*]], i64 1
; CHECK-NOMEMSSA-NEXT:    [[PV:%.*]] = load i32, i32* [[P]], align 4
; CHECK-NOMEMSSA-NEXT:    [[QV:%.*]] = load i32, i32* [[Q]], align 4
; CHECK-NOMEMSSA-NEXT:    call void @llvm.lifetime.end.p0i32(i64 8, i32* [[P]])
; CHECK-NOMEMSSA-NEXT:    call void @llvm.lifetime.start.p0i32(i64 8, i32* [[P]])
; CHECK-NOMEMSSA-NEXT:    store i32 [[PV]], i32* [[P]], align 4
; CHECK-NOMEMSSA-NEXT:    store i32 [[QV]], i32* [[Q]], align 4
; CHECK-NOMEMSSA-NEXT:    ret void
;
; CHECK-LABEL: @test_writeback_lifetimes(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[Q:%.*]] = getelementptr i32, i32* [[P:%.*]], i64 1
; CHECK-NEXT:    [[PV:%.*]] = load i32, i32* [[P]], align 4
; CHECK-NEXT:    [[QV:%.*]] = load i32, i32* [[Q]], align 4
; CHECK-NEXT:    call void @llvm.lifetime.end.p0i32(i64 8, i32* [[P]])
; CHECK-NEXT:    call void @llvm.lifetime.start.p0i32(i64 8, i32* [[P]])
; CHECK-NEXT:    store i32 [[PV]], i32* [[P]], align 4
; CHECK-NEXT:    store i32 [[QV]], i32* [[Q]], align 4
; CHECK-NEXT:    ret void
;
entry:
  %q = getelementptr i32, i32* %p, i64 1
  %pv = load i32, i32* %p
  %qv = load i32, i32* %q
  call void @llvm.lifetime.end.p0i8(i64 8, i32* %p)
  call void @llvm.lifetime.start.p0i8(i64 8, i32* %p)
  store i32 %pv, i32* %p
  store i32 %qv, i32* %q
  ret void
}

;; Check that we respect lifetime.start/lifetime.end intrinsics when deleting
;; stores that, without the lifetime calls, would be writebacks.
define void @test_writeback_lifetimes_multi_arg(i32* %p, i32* %q) {
; CHECK-NOMEMSSA-LABEL: @test_writeback_lifetimes_multi_arg(
; CHECK-NOMEMSSA-NEXT:  entry:
; CHECK-NOMEMSSA-NEXT:    [[PV:%.*]] = load i32, i32* [[P:%.*]], align 4
; CHECK-NOMEMSSA-NEXT:    [[QV:%.*]] = load i32, i32* [[Q:%.*]], align 4
; CHECK-NOMEMSSA-NEXT:    call void @llvm.lifetime.end.p0i32(i64 8, i32* [[P]])
; CHECK-NOMEMSSA-NEXT:    call void @llvm.lifetime.start.p0i32(i64 8, i32* [[P]])
; CHECK-NOMEMSSA-NEXT:    store i32 [[PV]], i32* [[P]], align 4
; CHECK-NOMEMSSA-NEXT:    store i32 [[QV]], i32* [[Q]], align 4
; CHECK-NOMEMSSA-NEXT:    ret void
;
; CHECK-LABEL: @test_writeback_lifetimes_multi_arg(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[PV:%.*]] = load i32, i32* [[P:%.*]], align 4
; CHECK-NEXT:    [[QV:%.*]] = load i32, i32* [[Q:%.*]], align 4
; CHECK-NEXT:    call void @llvm.lifetime.end.p0i32(i64 8, i32* [[P]])
; CHECK-NEXT:    call void @llvm.lifetime.start.p0i32(i64 8, i32* [[P]])
; CHECK-NEXT:    store i32 [[PV]], i32* [[P]], align 4
; CHECK-NEXT:    store i32 [[QV]], i32* [[Q]], align 4
; CHECK-NEXT:    ret void
;
entry:
  %pv = load i32, i32* %p
  %qv = load i32, i32* %q
  call void @llvm.lifetime.end.p0i8(i64 8, i32* %p)
  call void @llvm.lifetime.start.p0i8(i64 8, i32* %p)
  store i32 %pv, i32* %p
  store i32 %qv, i32* %q
  ret void
}

declare void @llvm.lifetime.end.p0i8(i64, i32*)
declare void @llvm.lifetime.start.p0i8(i64, i32*)
