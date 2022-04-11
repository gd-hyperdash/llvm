; NOTE: Assertions have been autogenerated by utils/update_analyze_test_checks.py
; RUN: opt -disable-output "-passes=print<scalar-evolution>" < %s 2>&1 | FileCheck %s

; Tests for smin & smax folds.

; Test case from PR1614.
define i32 @test_PR1614(i32 %a, i32 %b, i32 %c) {
; CHECK-LABEL: 'test_PR1614'
; CHECK: -->  (%a smax %b)
; CHECK: -->  (%a smax %b smax %c)
; CHECK-NOT: smax

  %A = icmp sgt i32 %a, %b
  %B = select i1 %A, i32 %a, i32 %b
  %C = icmp sle i32 %c, %B
  %D = select i1 %C, i32 %B, i32 %c
  ret i32 %D
}

declare void @iteration()

; Test case from PR46939.
; The information from the loop guard can be used to simplify the trip count expression.
define void @smin_simplify_with_guard(i32 %n) {
; CHECK-LABEL: 'smin_simplify_with_guard'
; CHECK-NEXT:  Classifying expressions for: @smin_simplify_with_guard
; CHECK-NEXT:    %i.011 = phi i32 [ %n, %for.body.lr.ph ], [ %dec, %for.body ]
; CHECK-NEXT:    --> {%n,+,-1}<nsw><%for.body> U: full-set S: full-set Exits: 0 LoopDispositions: { %for.body: Computable }
; CHECK-NEXT:    %dec = add nsw i32 %i.011, -1
; CHECK-NEXT:    --> {(-1 + %n),+,-1}<nw><%for.body> U: full-set S: full-set Exits: -1 LoopDispositions: { %for.body: Computable }
; CHECK-NEXT:  Determining loop execution counts for: @smin_simplify_with_guard
; CHECK-NEXT:  Loop %for.body: backedge-taken count is %n
; CHECK-NEXT:  Loop %for.body: max backedge-taken count is 2147483647
; CHECK-NEXT:  Loop %for.body: Predicated backedge-taken count is %n
; CHECK-NEXT:   Predicates:
; CHECK:       Loop %for.body: Trip multiple is 1
;
entry:
  %cmp10 = icmp sgt i32 %n, -1
  br i1 %cmp10, label %for.body.lr.ph, label %for.cond.cleanup

for.body.lr.ph:
  br label %for.body

for.body:
  %i.011 = phi i32 [ %n, %for.body.lr.ph ], [ %dec, %for.body ]
  call void @iteration()
  %dec = add nsw i32 %i.011, -1
  %cmp = icmp sgt i32 %i.011, 0
  br i1 %cmp, label %for.body, label %for.cond.cleanup.loopexit

for.cond.cleanup.loopexit:
  br label %for.cond.cleanup

for.cond.cleanup:
  ret void
}

define void @smin_to_smax(i32 %n) {
; FIXME: ((-1 * (0 smin %n)) + %n)  is actually just  (0 smax %n)

; CHECK-LABEL: 'smin_to_smax'
; CHECK-NEXT:  Classifying expressions for: @smin_to_smax
; CHECK-NEXT:    %i.011 = phi i32 [ %n, %for.body.lr.ph ], [ %dec, %for.body ]
; CHECK-NEXT:    --> {%n,+,-1}<nsw><%for.body> U: full-set S: full-set Exits: (0 smin %n) LoopDispositions: { %for.body: Computable }
; CHECK-NEXT:    %dec = add nsw i32 %i.011, -1
; CHECK-NEXT:    --> {(-1 + %n),+,-1}<nw><%for.body> U: full-set S: full-set Exits: (-1 + (0 smin %n)) LoopDispositions: { %for.body: Computable }
; CHECK-NEXT:  Determining loop execution counts for: @smin_to_smax
; CHECK-NEXT:  Loop %for.body: backedge-taken count is ((-1 * (0 smin %n)) + %n)
; CHECK-NEXT:  Loop %for.body: max backedge-taken count is 2147483647
; CHECK-NEXT:  Loop %for.body: Predicated backedge-taken count is ((-1 * (0 smin %n)) + %n)
; CHECK-NEXT:   Predicates:
; CHECK:       Loop %for.body: Trip multiple is 1
;
entry:
  br label %for.body.lr.ph

for.body.lr.ph:
  br label %for.body

for.body:
  %i.011 = phi i32 [ %n, %for.body.lr.ph ], [ %dec, %for.body ]
  call void @iteration()
  %dec = add nsw i32 %i.011, -1
  %cmp = icmp sgt i32 %i.011, 0
  br i1 %cmp, label %for.body, label %for.cond.cleanup.loopexit

for.cond.cleanup.loopexit:
  br label %for.cond.cleanup

for.cond.cleanup:
  ret void
}

; The information from the loop guard can be used to simplify the trip count expression.
define void @smax_simplify_with_guard(i32 %start, i32 %n) {
; CHECK-LABEL:  'smax_simplify_with_guard'
; CHECK-NEXT:  Classifying expressions for: @smax_simplify_with_guard
; CHECK-NEXT:    %k.0.i26 = phi i32 [ %start, %loop.ph ], [ %inc.i, %loop ]
; CHECK-NEXT:    -->  {%start,+,1}<nsw><%loop> U: full-set S: full-set      Exits: %n     LoopDispositions: { %loop: Computable }
; CHECK-NEXT:    %inc.i = add nsw i32 %k.0.i26, 1
; CHECK-NEXT:    -->  {(1 + %start),+,1}<nw><%loop> U: full-set S: full-set     Exits: (1 + %n)       LoopDispositions: { %loop: Computable }
; CHECK-NEXT:  Determining loop execution counts for: @smax_simplify_with_guard
; CHECK-NEXT:  Loop %loop: backedge-taken count is ((-1 * %start) + %n)
; CHECK-NEXT:  Loop %loop: max backedge-taken count is -1
; CHECK-NEXT:  Loop %loop: Predicated backedge-taken count is ((-1 * %start) +  %n)
; CHECK-NEXT:   Predicates:
; CHECK:       Loop %loop: Trip multiple is 1
entry:
  %guard = icmp sge i32 %n, %start
  br i1 %guard, label %loop.ph, label %exit

loop.ph:
  br label %loop

loop:
  %k.0.i26 = phi i32 [ %start, %loop.ph ], [ %inc.i, %loop ]
  %inc.i = add nsw i32 %k.0.i26, 1
  %cmp26.not.i.not = icmp slt i32 %k.0.i26, %n
  br i1 %cmp26.not.i.not, label %loop, label %exit

exit:
  ret void
}
