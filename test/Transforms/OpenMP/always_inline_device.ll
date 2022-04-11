; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --check-attributes
; RUN: opt < %s -S -passes=openmp-opt -openmp-opt-inline-device | FileCheck %s

%struct.ident_t = type { i32, i32, i32, i32, i8* }
@0 = private unnamed_addr constant [23 x i8] c";unknown;unknown;0;0;;\00", align 1
@1 = private unnamed_addr constant %struct.ident_t { i32 0, i32 2, i32 0, i32 0, i8* getelementptr inbounds ([23 x i8], [23 x i8]* @0, i32 0, i32 0) }, align 8
@__omp_offloading_fd02_c0934fc2_foo_l4_exec_mode = weak constant i8 1
@llvm.compiler.used = appending global [1 x i8*] [i8* @__omp_offloading_fd02_c0934fc2_foo_l4_exec_mode], section "llvm.metadata"
@G = external global i8

; Function Attrs: convergent norecurse nounwind
define weak void @__omp_offloading_fd02_c0934fc2_foo_l4() #0 {
; CHECK: Function Attrs: convergent norecurse nounwind
; CHECK-LABEL: @__omp_offloading_fd02_c0934fc2_foo_l4(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[TMP0:%.*]] = call i32 @__kmpc_target_init(%struct.ident_t* @[[GLOB1:[0-9]+]], i8 1, i1 false, i1 true)
; CHECK-NEXT:    [[EXEC_USER_CODE:%.*]] = icmp eq i32 [[TMP0]], -1
; CHECK-NEXT:    br i1 [[EXEC_USER_CODE]], label [[USER_CODE_ENTRY:%.*]], label [[WORKER_EXIT:%.*]]
; CHECK:       user_code.entry:
; CHECK-NEXT:    store i8 0, i8* @G, align 1
; CHECK-NEXT:    call void @__kmpc_target_deinit(%struct.ident_t* @[[GLOB1]], i8 1, i1 true)
; CHECK-NEXT:    ret void
; CHECK:       worker.exit:
; CHECK-NEXT:    ret void
;
entry:
  %0 = call i32 @__kmpc_target_init(%struct.ident_t* @1, i8 1, i1 true, i1 true)
  %exec_user_code = icmp eq i32 %0, -1
  br i1 %exec_user_code, label %user_code.entry, label %worker.exit

user_code.entry:                                  ; preds = %entry
  ; Ensure we see a 0 here as the kernel doesn't have parallel regions and we want
  ; generic execution.
  ; TODO: This is not perfect. We should rather go for SPMD mode and tell the runtime
  ;       to only spawn a single thread. Further, we then should not guard any code.
  %isSPMD = call i8 @__kmpc_is_spmd_exec_mode()
  store i8 %isSPMD, i8* @G
  call void @bar() #2
  call void @__kmpc_target_deinit(%struct.ident_t* @1, i8 1, i1 true)
  ret void

worker.exit:                                      ; preds = %entry
  ret void
}

declare i8 @__kmpc_is_spmd_exec_mode()

declare i32 @__kmpc_target_init(%struct.ident_t*, i8, i1, i1)

declare void @__kmpc_target_deinit(%struct.ident_t*, i8, i1)

; Function Attrs: convergent nounwind
define hidden void @bar() #1 {
; CHECK: Function Attrs: alwaysinline convergent nounwind
; CHECK-LABEL: @bar(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret void
;
entry:
  ret void
}

attributes #0 = { convergent norecurse nounwind "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="sm_70" "target-features"="+ptx32,+sm_70" }
attributes #1 = { convergent nounwind "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="sm_70" "target-features"="+ptx32,+sm_70" }
attributes #2 = { convergent }

!omp_offload.info = !{!0}
!nvvm.annotations = !{!1}
!llvm.module.flags = !{!2, !3, !4, !5, !6}
!llvm.ident = !{!7}

!0 = !{i32 0, i32 64770, i32 -1064087614, !"foo", i32 4, i32 0}
!1 = !{void ()* @__omp_offloading_fd02_c0934fc2_foo_l4, !"kernel", i32 1}
!2 = !{i32 1, !"wchar_size", i32 4}
!3 = !{i32 7, !"openmp", i32 50}
!4 = !{i32 7, !"openmp-device", i32 50}
!5 = !{i32 7, !"PIC Level", i32 2}
!6 = !{i32 7, !"frame-pointer", i32 2}
!7 = !{!"clang version 14.0.0"}
