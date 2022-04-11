; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -passes=constraint-elimination -S %s | FileCheck %s

declare void @use(i1)

define void @test_unsigned_too_large(i128 %x) {
; CHECK-LABEL: @test_unsigned_too_large(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[C_1:%.*]] = icmp ule i128 [[X:%.*]], 12345678901234123123123
; CHECK-NEXT:    br i1 [[C_1]], label [[BB1:%.*]], label [[BB2:%.*]]
; CHECK:       bb1:
; CHECK-NEXT:    [[C_2:%.*]] = icmp ult i128 [[X]], -12345678901234123123123
; CHECK-NEXT:    call void @use(i1 [[C_2]])
; CHECK-NEXT:    [[C_3:%.*]] = icmp uge i128 [[X]], -12345678901234123123123
; CHECK-NEXT:    call void @use(i1 [[C_3]])
; CHECK-NEXT:    [[C_4:%.*]] = icmp uge i128 [[X]], -12345678901234123123123
; CHECK-NEXT:    call void @use(i1 [[C_4]])
; CHECK-NEXT:    ret void
; CHECK:       bb2:
; CHECK-NEXT:    ret void
;
entry:
  %c.1 = icmp ule i128 %x, 12345678901234123123123
  br i1 %c.1, label %bb1, label %bb2

bb1:
  %c.2 = icmp ult i128 %x, -12345678901234123123123
  call void @use(i1 %c.2)
  %c.3 = icmp uge i128 %x, -12345678901234123123123
  call void @use(i1 %c.3)
  %c.4 = icmp uge i128 %x, -12345678901234123123123
  call void @use(i1 %c.4)
  ret void

bb2:
  ret void
}
