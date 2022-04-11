; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=aarch64-none-linux-gnu -mattr=+neon < %s -verify-machineinstrs | FileCheck %s

define <2 x i64> @v2i64(<2 x i64> %a) {
; CHECK-LABEL: v2i64:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    ext v0.16b, v0.16b, v0.16b, #8
; CHECK-NEXT:    ret
entry:
  %V128 = shufflevector <2 x i64> %a, <2 x i64> undef, <2 x i32> <i32 1, i32 0>
  ret <2 x i64> %V128
}

define <4 x i32> @v4i32(<4 x i32> %a) {
; CHECK-LABEL: v4i32:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    rev64 v0.4s, v0.4s
; CHECK-NEXT:    ext v0.16b, v0.16b, v0.16b, #8
; CHECK-NEXT:    ret
entry:
  %V128 = shufflevector <4 x i32> %a, <4 x i32> undef, <4 x i32> <i32 3, i32 2, i32 1, i32 0>
  ret <4 x i32> %V128
}

define <2 x i32> @v2i32(<2 x i32> %a) {
; CHECK-LABEL: v2i32:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    rev64 v0.2s, v0.2s
; CHECK-NEXT:    ret
entry:
  %V128 = shufflevector <2 x i32> %a, <2 x i32> undef, <2 x i32> <i32 1, i32 0>
  ret <2 x i32> %V128
}

define <8 x i16> @v8i16(<8 x i16> %a) {
; CHECK-LABEL: v8i16:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    rev64 v0.8h, v0.8h
; CHECK-NEXT:    ext v0.16b, v0.16b, v0.16b, #8
; CHECK-NEXT:    ret
entry:
  %V128 = shufflevector <8 x i16> %a, <8 x i16> undef, <8 x i32> <i32 7, i32 6, i32 5, i32 4, i32 3, i32 2, i32 1, i32 0>
  ret <8 x i16> %V128
}

define <8 x i16> @v8i16_2(<4 x i16> %a, <4 x i16> %b) {
; CHECK-LABEL: v8i16_2:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    rev64 v2.4h, v0.4h
; CHECK-NEXT:    rev64 v0.4h, v1.4h
; CHECK-NEXT:    mov v0.d[1], v2.d[0]
; CHECK-NEXT:    ret
entry:
  %V128 = shufflevector <4 x i16> %a, <4 x i16> %b, <8 x i32> <i32 7, i32 6, i32 5, i32 4, i32 3, i32 2, i32 1, i32 0>
  ret <8 x i16> %V128
}

define <4 x i16> @v4i16(<4 x i16> %a) {
; CHECK-LABEL: v4i16:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    rev64 v0.4h, v0.4h
; CHECK-NEXT:    ret
entry:
  %V128 = shufflevector <4 x i16> %a, <4 x i16> undef, <4 x i32> <i32 3, i32 2, i32 1, i32 0>
  ret <4 x i16> %V128
}

define <16 x i8> @v16i8(<16 x i8> %a) {
; CHECK-LABEL: v16i8:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    rev64 v0.16b, v0.16b
; CHECK-NEXT:    ext v0.16b, v0.16b, v0.16b, #8
; CHECK-NEXT:    ret
entry:
  %V128 = shufflevector <16 x i8> %a, <16 x i8> undef, <16 x i32> <i32 15, i32 14, i32 13, i32 12, i32 11, i32 10, i32 9, i32 8, i32 7, i32 6, i32 5, i32 4, i32 3, i32 2, i32 1, i32 0>
  ret <16 x i8> %V128
}

define <16 x i8> @v16i8_2(<8 x i8> %a, <8 x i8> %b) {
; CHECK-LABEL: v16i8_2:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    adrp x8, .LCPI7_0
; CHECK-NEXT:    // kill: def $d1 killed $d1 killed $q0_q1 def $q0_q1
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $q0_q1 def $q0_q1
; CHECK-NEXT:    ldr q2, [x8, :lo12:.LCPI7_0]
; CHECK-NEXT:    tbl v0.16b, { v0.16b, v1.16b }, v2.16b
; CHECK-NEXT:    ret
entry:
  %V128 = shufflevector <8 x i8> %a, <8 x i8> %b, <16 x i32> <i32 15, i32 14, i32 13, i32 12, i32 11, i32 10, i32 9, i32 8, i32 7, i32 6, i32 5, i32 4, i32 3, i32 2, i32 1, i32 0>
  ret <16 x i8> %V128
}

define <8 x i8> @v8i8(<8 x i8> %a) {
; CHECK-LABEL: v8i8:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    rev64 v0.8b, v0.8b
; CHECK-NEXT:    ret
entry:
  %V128 = shufflevector <8 x i8> %a, <8 x i8> undef, <8 x i32> <i32 7, i32 6, i32 5, i32 4, i32 3, i32 2, i32 1, i32 0>
  ret <8 x i8> %V128
}

define <2 x double> @v2f64(<2 x double> %a) {
; CHECK-LABEL: v2f64:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    ext v0.16b, v0.16b, v0.16b, #8
; CHECK-NEXT:    ret
entry:
  %V128 = shufflevector <2 x double> %a, <2 x double> undef, <2 x i32> <i32 1, i32 0>
  ret <2 x double> %V128
}

define <4 x float> @v4f32(<4 x float> %a) {
; CHECK-LABEL: v4f32:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    rev64 v0.4s, v0.4s
; CHECK-NEXT:    ext v0.16b, v0.16b, v0.16b, #8
; CHECK-NEXT:    ret
entry:
  %V128 = shufflevector <4 x float> %a, <4 x float> undef, <4 x i32> <i32 3, i32 2, i32 1, i32 0>
  ret <4 x float> %V128
}

define <2 x float> @v2f32(<2 x float> %a) {
; CHECK-LABEL: v2f32:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    rev64 v0.2s, v0.2s
; CHECK-NEXT:    ret
entry:
  %V128 = shufflevector <2 x float> %a, <2 x float> undef, <2 x i32> <i32 1, i32 0>
  ret <2 x float> %V128
}

define <8 x half> @v8f16(<8 x half> %a) {
; CHECK-LABEL: v8f16:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    rev64 v0.8h, v0.8h
; CHECK-NEXT:    ext v0.16b, v0.16b, v0.16b, #8
; CHECK-NEXT:    ret
entry:
  %V128 = shufflevector <8 x half> %a, <8 x half> undef, <8 x i32> <i32 7, i32 6, i32 5, i32 4, i32 3, i32 2, i32 1, i32 0>
  ret <8 x half> %V128
}

define <4 x half> @v4f16(<4 x half> %a) {
; CHECK-LABEL: v4f16:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    rev64 v0.4h, v0.4h
; CHECK-NEXT:    ret
entry:
  %V128 = shufflevector <4 x half> %a, <4 x half> undef, <4 x i32> <i32 3, i32 2, i32 1, i32 0>
  ret <4 x half> %V128
}
