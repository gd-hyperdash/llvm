; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -verify-machineinstrs -mtriple=powerpc64le-unknown-linux-gnu \
; RUN:   -mcpu=pwr9 < %s | FileCheck %s

define void @foo(double* readonly %0, double* %1, i64 %2, i64 %3, i64 %4, i64 %5, i64 %6, i64 %7) {
; CHECK-LABEL: foo:
; CHECK:       # %bb.0:
; CHECK-NEXT:    cmpd 5, 7
; CHECK-NEXT:    std 22, -80(1) # 8-byte Folded Spill
; CHECK-NEXT:    std 23, -72(1) # 8-byte Folded Spill
; CHECK-NEXT:    std 24, -64(1) # 8-byte Folded Spill
; CHECK-NEXT:    std 25, -56(1) # 8-byte Folded Spill
; CHECK-NEXT:    std 26, -48(1) # 8-byte Folded Spill
; CHECK-NEXT:    std 27, -40(1) # 8-byte Folded Spill
; CHECK-NEXT:    std 28, -32(1) # 8-byte Folded Spill
; CHECK-NEXT:    std 29, -24(1) # 8-byte Folded Spill
; CHECK-NEXT:    std 30, -16(1) # 8-byte Folded Spill
; CHECK-NEXT:    bge 0, .LBB0_6
; CHECK-NEXT:  # %bb.1: # %.preheader
; CHECK-NEXT:    addi 30, 5, 1
; CHECK-NEXT:    addi 28, 5, 3
; CHECK-NEXT:    addi 27, 5, 2
; CHECK-NEXT:    mulld 12, 8, 5
; CHECK-NEXT:    addi 29, 3, 16
; CHECK-NEXT:    mulld 0, 9, 8
; CHECK-NEXT:    sldi 11, 10, 3
; CHECK-NEXT:    mulld 30, 8, 30
; CHECK-NEXT:    mulld 28, 8, 28
; CHECK-NEXT:    mulld 8, 8, 27
; CHECK-NEXT:    b .LBB0_3
; CHECK-NEXT:    .p2align 4
; CHECK-NEXT:  .LBB0_2:
; CHECK-NEXT:    add 5, 5, 9
; CHECK-NEXT:    add 12, 12, 0
; CHECK-NEXT:    add 30, 30, 0
; CHECK-NEXT:    add 28, 28, 0
; CHECK-NEXT:    add 8, 8, 0
; CHECK-NEXT:    cmpd 5, 7
; CHECK-NEXT:    bge 0, .LBB0_6
; CHECK-NEXT:  .LBB0_3: # =>This Loop Header: Depth=1
; CHECK-NEXT:    # Child Loop BB0_5 Depth 2
; CHECK-NEXT:    sub 27, 5, 10
; CHECK-NEXT:    cmpd 6, 27
; CHECK-NEXT:    bge 0, .LBB0_2
; CHECK-NEXT:  # %bb.4:
; CHECK-NEXT:    add 23, 6, 12
; CHECK-NEXT:    add 22, 6, 30
; CHECK-NEXT:    add 25, 6, 28
; CHECK-NEXT:    add 24, 6, 8
; CHECK-NEXT:    sldi 26, 6, 3
; CHECK-NEXT:    sldi 25, 25, 3
; CHECK-NEXT:    sldi 24, 24, 3
; CHECK-NEXT:    sldi 23, 23, 3
; CHECK-NEXT:    sldi 22, 22, 3
; CHECK-NEXT:    add 26, 4, 26
; CHECK-NEXT:    add 25, 29, 25
; CHECK-NEXT:    add 24, 29, 24
; CHECK-NEXT:    add 23, 3, 23
; CHECK-NEXT:    add 22, 3, 22
; CHECK-NEXT:    .p2align 5
; CHECK-NEXT:  .LBB0_5: # Parent Loop BB0_3 Depth=1
; CHECK-NEXT:    # => This Inner Loop Header: Depth=2
; CHECK-NEXT:    lfd 0, 0(26)
; CHECK-NEXT:    lfd 1, 0(23)
; CHECK-NEXT:    add 6, 6, 10
; CHECK-NEXT:    cmpd 6, 27
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, 8(23)
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, 16(23)
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, 24(23)
; CHECK-NEXT:    add 23, 23, 11
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, 0(22)
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, 8(22)
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, 16(22)
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, 24(22)
; CHECK-NEXT:    add 22, 22, 11
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, -16(24)
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, -8(24)
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, 0(24)
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, 8(24)
; CHECK-NEXT:    add 24, 24, 11
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, -16(25)
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, -8(25)
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, 0(25)
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    lfd 1, 8(25)
; CHECK-NEXT:    add 25, 25, 11
; CHECK-NEXT:    xsadddp 0, 0, 1
; CHECK-NEXT:    stfd 0, 0(26)
; CHECK-NEXT:    add 26, 26, 11
; CHECK-NEXT:    blt 0, .LBB0_5
; CHECK-NEXT:    b .LBB0_2
; CHECK-NEXT:  .LBB0_6:
; CHECK-NEXT:    ld 30, -16(1) # 8-byte Folded Reload
; CHECK-NEXT:    ld 29, -24(1) # 8-byte Folded Reload
; CHECK-NEXT:    ld 28, -32(1) # 8-byte Folded Reload
; CHECK-NEXT:    ld 27, -40(1) # 8-byte Folded Reload
; CHECK-NEXT:    ld 26, -48(1) # 8-byte Folded Reload
; CHECK-NEXT:    ld 25, -56(1) # 8-byte Folded Reload
; CHECK-NEXT:    ld 24, -64(1) # 8-byte Folded Reload
; CHECK-NEXT:    ld 23, -72(1) # 8-byte Folded Reload
; CHECK-NEXT:    ld 22, -80(1) # 8-byte Folded Reload
; CHECK-NEXT:    blr
  %9 = icmp slt i64 %2, %4
  br i1 %9, label %10, label %97

10:                                               ; preds = %8, %93
  %11 = phi i64 [ %95, %93 ], [ %2, %8 ]
  %12 = phi i64 [ %94, %93 ], [ %3, %8 ]
  %13 = sub nsw i64 %11, %7
  %14 = icmp slt i64 %12, %13
  br i1 %14, label %15, label %93

15:                                               ; preds = %10
  %16 = mul nsw i64 %11, %5
  %17 = add nsw i64 %11, 1
  %18 = mul nsw i64 %17, %5
  %19 = add nsw i64 %11, 2
  %20 = mul nsw i64 %19, %5
  %21 = add nsw i64 %11, 3
  %22 = mul nsw i64 %21, %5
  br label %23

23:                                               ; preds = %15, %23
  %24 = phi i64 [ %12, %15 ], [ %91, %23 ]
  %25 = getelementptr inbounds double, double* %1, i64 %24
  %26 = load double, double* %25, align 8
  %27 = add nsw i64 %24, %16
  %28 = getelementptr inbounds double, double* %0, i64 %27
  %29 = load double, double* %28, align 8
  %30 = fadd double %26, %29
  %31 = add nsw i64 %27, 1
  %32 = getelementptr inbounds double, double* %0, i64 %31
  %33 = load double, double* %32, align 8
  %34 = fadd double %30, %33
  %35 = add nsw i64 %27, 2
  %36 = getelementptr inbounds double, double* %0, i64 %35
  %37 = load double, double* %36, align 8
  %38 = fadd double %34, %37
  %39 = add nsw i64 %27, 3
  %40 = getelementptr inbounds double, double* %0, i64 %39
  %41 = load double, double* %40, align 8
  %42 = fadd double %38, %41
  %43 = add nsw i64 %24, %18
  %44 = getelementptr inbounds double, double* %0, i64 %43
  %45 = load double, double* %44, align 8
  %46 = fadd double %42, %45
  %47 = add nsw i64 %43, 1
  %48 = getelementptr inbounds double, double* %0, i64 %47
  %49 = load double, double* %48, align 8
  %50 = fadd double %46, %49
  %51 = add nsw i64 %43, 2
  %52 = getelementptr inbounds double, double* %0, i64 %51
  %53 = load double, double* %52, align 8
  %54 = fadd double %50, %53
  %55 = add nsw i64 %43, 3
  %56 = getelementptr inbounds double, double* %0, i64 %55
  %57 = load double, double* %56, align 8
  %58 = fadd double %54, %57
  %59 = add nsw i64 %24, %20
  %60 = getelementptr inbounds double, double* %0, i64 %59
  %61 = load double, double* %60, align 8
  %62 = fadd double %58, %61
  %63 = add nsw i64 %59, 1
  %64 = getelementptr inbounds double, double* %0, i64 %63
  %65 = load double, double* %64, align 8
  %66 = fadd double %62, %65
  %67 = add nsw i64 %59, 2
  %68 = getelementptr inbounds double, double* %0, i64 %67
  %69 = load double, double* %68, align 8
  %70 = fadd double %66, %69
  %71 = add nsw i64 %59, 3
  %72 = getelementptr inbounds double, double* %0, i64 %71
  %73 = load double, double* %72, align 8
  %74 = fadd double %70, %73
  %75 = add nsw i64 %24, %22
  %76 = getelementptr inbounds double, double* %0, i64 %75
  %77 = load double, double* %76, align 8
  %78 = fadd double %74, %77
  %79 = add nsw i64 %75, 1
  %80 = getelementptr inbounds double, double* %0, i64 %79
  %81 = load double, double* %80, align 8
  %82 = fadd double %78, %81
  %83 = add nsw i64 %75, 2
  %84 = getelementptr inbounds double, double* %0, i64 %83
  %85 = load double, double* %84, align 8
  %86 = fadd double %82, %85
  %87 = add nsw i64 %75, 3
  %88 = getelementptr inbounds double, double* %0, i64 %87
  %89 = load double, double* %88, align 8
  %90 = fadd double %86, %89
  store double %90, double* %25, align 8
  %91 = add nsw i64 %24, %7
  %92 = icmp slt i64 %91, %13
  br i1 %92, label %23, label %93

93:                                               ; preds = %23, %10
  %94 = phi i64 [ %12, %10 ], [ %91, %23 ]
  %95 = add nsw i64 %11, %6
  %96 = icmp slt i64 %95, %4
  br i1 %96, label %10, label %97

97:                                               ; preds = %93, %8
  ret void
}
