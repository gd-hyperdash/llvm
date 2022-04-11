; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --include-generated-funcs
; RUN: opt -S -verify -iroutliner -ir-outlining-no-cost < %s | FileCheck %s

; Show that we are able to extract blocks that contain PHINodes, and selectively
; store into it's respective block, only using if needed.

define void @function1(i32* %a, i32* %b) {
entry:
  %0 = alloca i32, align 4
  %c = load i32, i32* %0, align 4
  br label %test1
test1:
  %e = load i32, i32* %0, align 4
  br label %first
test:
  %d = load i32, i32* %0, align 4
  br label %first
first:
  %1 = phi i32 [ %c, %test ], [ %e, %test1 ]
  ret void
}

define void @function2(i32* %a, i32* %b) {
entry:
  %0 = alloca i32, align 4
  %c = load i32, i32* %0, align 4
  br label %test1
test1:
  %e = load i32, i32* %0, align 4
  br label %first
test:
  %d = load i32, i32* %0, align 4
  br label %first
first:
  ret void
}
; CHECK-LABEL: @function1(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[DOTCE_LOC:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[TMP0:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[LT_CAST:%.*]] = bitcast i32* [[DOTCE_LOC]] to i8*
; CHECK-NEXT:    call void @llvm.lifetime.start.p0i8(i64 -1, i8* [[LT_CAST]])
; CHECK-NEXT:    call void @outlined_ir_func_0(i32* [[TMP0]], i32* [[DOTCE_LOC]], i32 0)
; CHECK-NEXT:    [[DOTCE_RELOAD:%.*]] = load i32, i32* [[DOTCE_LOC]], align 4
; CHECK-NEXT:    call void @llvm.lifetime.end.p0i8(i64 -1, i8* [[LT_CAST]])
; CHECK-NEXT:    br label [[FIRST:%.*]]
; CHECK:       first:
; CHECK-NEXT:    [[TMP1:%.*]] = phi i32 [ [[DOTCE_RELOAD]], [[ENTRY:%.*]] ]
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: @function2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[TMP0:%.*]] = alloca i32, align 4
; CHECK-NEXT:    call void @outlined_ir_func_0(i32* [[TMP0]], i32* null, i32 -1)
; CHECK-NEXT:    br label [[FIRST:%.*]]
; CHECK:       first:
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define internal void  @outlined_ir_func_0(
; CHECK-NEXT:  newFuncRoot:
; CHECK-NEXT:    br label [[ENTRY_TO_OUTLINE:%.*]]
; CHECK:       entry_to_outline:
; CHECK-NEXT:    [[C:%.*]] = load i32, i32* [[TMP0:%.*]], align 4
; CHECK-NEXT:    br label [[TEST1:%.*]]
; CHECK:       test1:
; CHECK-NEXT:    [[E:%.*]] = load i32, i32* [[TMP0]], align 4
; CHECK-NEXT:    br label [[FIRST_SPLIT:%.*]]
; CHECK:       test:
; CHECK-NEXT:    [[D:%.*]] = load i32, i32* [[TMP0]], align 4
; CHECK-NEXT:    br label [[FIRST_SPLIT]]
; CHECK:       first.split:
; CHECK-NEXT:    [[DOTCE:%.*]] = phi i32 [ [[C]], [[TEST:%.*]] ], [ [[E]], [[TEST1]] ]
; CHECK-NEXT:    br label [[FIRST_EXITSTUB:%.*]]
; CHECK:       first.exitStub:
; CHECK-NEXT:    switch i32 [[TMP2:%.*]], label [[FINAL_BLOCK_0:%.*]] [
; CHECK-NEXT:    i32 0, label [[OUTPUT_BLOCK_0_0:%.*]]
; CHECK-NEXT:    ]
; CHECK:       output_block_0_0:
; CHECK-NEXT:    store i32 [[DOTCE]], i32* [[TMP1:%.*]], align 4
; CHECK-NEXT:    br label [[FINAL_BLOCK_0]]
; CHECK:       final_block_0:
; CHECK-NEXT:    ret void
;
