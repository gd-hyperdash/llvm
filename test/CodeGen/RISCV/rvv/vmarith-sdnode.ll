; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=riscv32 -mattr=+v -verify-machineinstrs < %s | FileCheck %s
; RUN: llc -mtriple=riscv64 -mattr=+v -verify-machineinstrs < %s | FileCheck %s

define <vscale x 1 x i1> @vmand_vv_nxv1i1(<vscale x 1 x i1> %va, <vscale x 1 x i1> %vb) {
; CHECK-LABEL: vmand_vv_nxv1i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf8, ta, mu
; CHECK-NEXT:    vmand.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = and <vscale x 1 x i1> %va, %vb
  ret <vscale x 1 x i1> %vc
}

define <vscale x 2 x i1> @vmand_vv_nxv2i1(<vscale x 2 x i1> %va, <vscale x 2 x i1> %vb) {
; CHECK-LABEL: vmand_vv_nxv2i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf4, ta, mu
; CHECK-NEXT:    vmand.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = and <vscale x 2 x i1> %va, %vb
  ret <vscale x 2 x i1> %vc
}

define <vscale x 4 x i1> @vmand_vv_nxv4i1(<vscale x 4 x i1> %va, <vscale x 4 x i1> %vb) {
; CHECK-LABEL: vmand_vv_nxv4i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf2, ta, mu
; CHECK-NEXT:    vmand.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = and <vscale x 4 x i1> %va, %vb
  ret <vscale x 4 x i1> %vc
}

define <vscale x 8 x i1> @vmand_vv_nxv8i1(<vscale x 8 x i1> %va, <vscale x 8 x i1> %vb) {
; CHECK-LABEL: vmand_vv_nxv8i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m1, ta, mu
; CHECK-NEXT:    vmand.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = and <vscale x 8 x i1> %va, %vb
  ret <vscale x 8 x i1> %vc
}

define <vscale x 16 x i1> @vmand_vv_nxv16i1(<vscale x 16 x i1> %va, <vscale x 16 x i1> %vb) {
; CHECK-LABEL: vmand_vv_nxv16i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m2, ta, mu
; CHECK-NEXT:    vmand.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = and <vscale x 16 x i1> %va, %vb
  ret <vscale x 16 x i1> %vc
}

define <vscale x 1 x i1> @vmor_vv_nxv1i1(<vscale x 1 x i1> %va, <vscale x 1 x i1> %vb) {
; CHECK-LABEL: vmor_vv_nxv1i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf8, ta, mu
; CHECK-NEXT:    vmor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = or <vscale x 1 x i1> %va, %vb
  ret <vscale x 1 x i1> %vc
}

define <vscale x 2 x i1> @vmor_vv_nxv2i1(<vscale x 2 x i1> %va, <vscale x 2 x i1> %vb) {
; CHECK-LABEL: vmor_vv_nxv2i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf4, ta, mu
; CHECK-NEXT:    vmor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = or <vscale x 2 x i1> %va, %vb
  ret <vscale x 2 x i1> %vc
}

define <vscale x 4 x i1> @vmor_vv_nxv4i1(<vscale x 4 x i1> %va, <vscale x 4 x i1> %vb) {
; CHECK-LABEL: vmor_vv_nxv4i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf2, ta, mu
; CHECK-NEXT:    vmor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = or <vscale x 4 x i1> %va, %vb
  ret <vscale x 4 x i1> %vc
}

define <vscale x 8 x i1> @vmor_vv_nxv8i1(<vscale x 8 x i1> %va, <vscale x 8 x i1> %vb) {
; CHECK-LABEL: vmor_vv_nxv8i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m1, ta, mu
; CHECK-NEXT:    vmor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = or <vscale x 8 x i1> %va, %vb
  ret <vscale x 8 x i1> %vc
}

define <vscale x 16 x i1> @vmor_vv_nxv16i1(<vscale x 16 x i1> %va, <vscale x 16 x i1> %vb) {
; CHECK-LABEL: vmor_vv_nxv16i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m2, ta, mu
; CHECK-NEXT:    vmor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = or <vscale x 16 x i1> %va, %vb
  ret <vscale x 16 x i1> %vc
}

define <vscale x 1 x i1> @vmxor_vv_nxv1i1(<vscale x 1 x i1> %va, <vscale x 1 x i1> %vb) {
; CHECK-LABEL: vmxor_vv_nxv1i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf8, ta, mu
; CHECK-NEXT:    vmxor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = xor <vscale x 1 x i1> %va, %vb
  ret <vscale x 1 x i1> %vc
}

define <vscale x 2 x i1> @vmxor_vv_nxv2i1(<vscale x 2 x i1> %va, <vscale x 2 x i1> %vb) {
; CHECK-LABEL: vmxor_vv_nxv2i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf4, ta, mu
; CHECK-NEXT:    vmxor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = xor <vscale x 2 x i1> %va, %vb
  ret <vscale x 2 x i1> %vc
}

define <vscale x 4 x i1> @vmxor_vv_nxv4i1(<vscale x 4 x i1> %va, <vscale x 4 x i1> %vb) {
; CHECK-LABEL: vmxor_vv_nxv4i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf2, ta, mu
; CHECK-NEXT:    vmxor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = xor <vscale x 4 x i1> %va, %vb
  ret <vscale x 4 x i1> %vc
}

define <vscale x 8 x i1> @vmxor_vv_nxv8i1(<vscale x 8 x i1> %va, <vscale x 8 x i1> %vb) {
; CHECK-LABEL: vmxor_vv_nxv8i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m1, ta, mu
; CHECK-NEXT:    vmxor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = xor <vscale x 8 x i1> %va, %vb
  ret <vscale x 8 x i1> %vc
}

define <vscale x 16 x i1> @vmxor_vv_nxv16i1(<vscale x 16 x i1> %va, <vscale x 16 x i1> %vb) {
; CHECK-LABEL: vmxor_vv_nxv16i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m2, ta, mu
; CHECK-NEXT:    vmxor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = xor <vscale x 16 x i1> %va, %vb
  ret <vscale x 16 x i1> %vc
}

define <vscale x 1 x i1> @vmnand_vv_nxv1i1(<vscale x 1 x i1> %va, <vscale x 1 x i1> %vb) {
; CHECK-LABEL: vmnand_vv_nxv1i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf8, ta, mu
; CHECK-NEXT:    vmnand.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = and <vscale x 1 x i1> %va, %vb
  %head = insertelement <vscale x 1 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 1 x i1> %head, <vscale x 1 x i1> poison, <vscale x 1 x i32> zeroinitializer
  %not = xor <vscale x 1 x i1> %vc, %splat
  ret <vscale x 1 x i1> %not
}

define <vscale x 2 x i1> @vmnand_vv_nxv2i1(<vscale x 2 x i1> %va, <vscale x 2 x i1> %vb) {
; CHECK-LABEL: vmnand_vv_nxv2i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf4, ta, mu
; CHECK-NEXT:    vmnand.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = and <vscale x 2 x i1> %va, %vb
  %head = insertelement <vscale x 2 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 2 x i1> %head, <vscale x 2 x i1> poison, <vscale x 2 x i32> zeroinitializer
  %not = xor <vscale x 2 x i1> %vc, %splat
  ret <vscale x 2 x i1> %not
}

define <vscale x 4 x i1> @vmnand_vv_nxv4i1(<vscale x 4 x i1> %va, <vscale x 4 x i1> %vb) {
; CHECK-LABEL: vmnand_vv_nxv4i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf2, ta, mu
; CHECK-NEXT:    vmnand.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = and <vscale x 4 x i1> %va, %vb
  %head = insertelement <vscale x 4 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 4 x i1> %head, <vscale x 4 x i1> poison, <vscale x 4 x i32> zeroinitializer
  %not = xor <vscale x 4 x i1> %vc, %splat
  ret <vscale x 4 x i1> %not
}

define <vscale x 8 x i1> @vmnand_vv_nxv8i1(<vscale x 8 x i1> %va, <vscale x 8 x i1> %vb) {
; CHECK-LABEL: vmnand_vv_nxv8i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m1, ta, mu
; CHECK-NEXT:    vmnand.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = and <vscale x 8 x i1> %va, %vb
  %head = insertelement <vscale x 8 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 8 x i1> %head, <vscale x 8 x i1> poison, <vscale x 8 x i32> zeroinitializer
  %not = xor <vscale x 8 x i1> %vc, %splat
  ret <vscale x 8 x i1> %not
}

define <vscale x 16 x i1> @vmnand_vv_nxv16i1(<vscale x 16 x i1> %va, <vscale x 16 x i1> %vb) {
; CHECK-LABEL: vmnand_vv_nxv16i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m2, ta, mu
; CHECK-NEXT:    vmnand.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = and <vscale x 16 x i1> %va, %vb
  %head = insertelement <vscale x 16 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 16 x i1> %head, <vscale x 16 x i1> poison, <vscale x 16 x i32> zeroinitializer
  %not = xor <vscale x 16 x i1> %vc, %splat
  ret <vscale x 16 x i1> %not
}

define <vscale x 1 x i1> @vmnor_vv_nxv1i1(<vscale x 1 x i1> %va, <vscale x 1 x i1> %vb) {
; CHECK-LABEL: vmnor_vv_nxv1i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf8, ta, mu
; CHECK-NEXT:    vmnor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = or <vscale x 1 x i1> %va, %vb
  %head = insertelement <vscale x 1 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 1 x i1> %head, <vscale x 1 x i1> poison, <vscale x 1 x i32> zeroinitializer
  %not = xor <vscale x 1 x i1> %vc, %splat
  ret <vscale x 1 x i1> %not
}

define <vscale x 2 x i1> @vmnor_vv_nxv2i1(<vscale x 2 x i1> %va, <vscale x 2 x i1> %vb) {
; CHECK-LABEL: vmnor_vv_nxv2i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf4, ta, mu
; CHECK-NEXT:    vmnor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = or <vscale x 2 x i1> %va, %vb
  %head = insertelement <vscale x 2 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 2 x i1> %head, <vscale x 2 x i1> poison, <vscale x 2 x i32> zeroinitializer
  %not = xor <vscale x 2 x i1> %vc, %splat
  ret <vscale x 2 x i1> %not
}

define <vscale x 4 x i1> @vmnor_vv_nxv4i1(<vscale x 4 x i1> %va, <vscale x 4 x i1> %vb) {
; CHECK-LABEL: vmnor_vv_nxv4i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf2, ta, mu
; CHECK-NEXT:    vmnor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = or <vscale x 4 x i1> %va, %vb
  %head = insertelement <vscale x 4 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 4 x i1> %head, <vscale x 4 x i1> poison, <vscale x 4 x i32> zeroinitializer
  %not = xor <vscale x 4 x i1> %vc, %splat
  ret <vscale x 4 x i1> %not
}

define <vscale x 8 x i1> @vmnor_vv_nxv8i1(<vscale x 8 x i1> %va, <vscale x 8 x i1> %vb) {
; CHECK-LABEL: vmnor_vv_nxv8i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m1, ta, mu
; CHECK-NEXT:    vmnor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = or <vscale x 8 x i1> %va, %vb
  %head = insertelement <vscale x 8 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 8 x i1> %head, <vscale x 8 x i1> poison, <vscale x 8 x i32> zeroinitializer
  %not = xor <vscale x 8 x i1> %vc, %splat
  ret <vscale x 8 x i1> %not
}

define <vscale x 16 x i1> @vmnor_vv_nxv16i1(<vscale x 16 x i1> %va, <vscale x 16 x i1> %vb) {
; CHECK-LABEL: vmnor_vv_nxv16i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m2, ta, mu
; CHECK-NEXT:    vmnor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = or <vscale x 16 x i1> %va, %vb
  %head = insertelement <vscale x 16 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 16 x i1> %head, <vscale x 16 x i1> poison, <vscale x 16 x i32> zeroinitializer
  %not = xor <vscale x 16 x i1> %vc, %splat
  ret <vscale x 16 x i1> %not
}

define <vscale x 1 x i1> @vmxnor_vv_nxv1i1(<vscale x 1 x i1> %va, <vscale x 1 x i1> %vb) {
; CHECK-LABEL: vmxnor_vv_nxv1i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf8, ta, mu
; CHECK-NEXT:    vmxnor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = xor <vscale x 1 x i1> %va, %vb
  %head = insertelement <vscale x 1 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 1 x i1> %head, <vscale x 1 x i1> poison, <vscale x 1 x i32> zeroinitializer
  %not = xor <vscale x 1 x i1> %vc, %splat
  ret <vscale x 1 x i1> %not
}

define <vscale x 2 x i1> @vmxnor_vv_nxv2i1(<vscale x 2 x i1> %va, <vscale x 2 x i1> %vb) {
; CHECK-LABEL: vmxnor_vv_nxv2i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf4, ta, mu
; CHECK-NEXT:    vmxnor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = xor <vscale x 2 x i1> %va, %vb
  %head = insertelement <vscale x 2 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 2 x i1> %head, <vscale x 2 x i1> poison, <vscale x 2 x i32> zeroinitializer
  %not = xor <vscale x 2 x i1> %vc, %splat
  ret <vscale x 2 x i1> %not
}

define <vscale x 4 x i1> @vmxnor_vv_nxv4i1(<vscale x 4 x i1> %va, <vscale x 4 x i1> %vb) {
; CHECK-LABEL: vmxnor_vv_nxv4i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf2, ta, mu
; CHECK-NEXT:    vmxnor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = xor <vscale x 4 x i1> %va, %vb
  %head = insertelement <vscale x 4 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 4 x i1> %head, <vscale x 4 x i1> poison, <vscale x 4 x i32> zeroinitializer
  %not = xor <vscale x 4 x i1> %vc, %splat
  ret <vscale x 4 x i1> %not
}

define <vscale x 8 x i1> @vmxnor_vv_nxv8i1(<vscale x 8 x i1> %va, <vscale x 8 x i1> %vb) {
; CHECK-LABEL: vmxnor_vv_nxv8i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m1, ta, mu
; CHECK-NEXT:    vmxnor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = xor <vscale x 8 x i1> %va, %vb
  %head = insertelement <vscale x 8 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 8 x i1> %head, <vscale x 8 x i1> poison, <vscale x 8 x i32> zeroinitializer
  %not = xor <vscale x 8 x i1> %vc, %splat
  ret <vscale x 8 x i1> %not
}

define <vscale x 16 x i1> @vmxnor_vv_nxv16i1(<vscale x 16 x i1> %va, <vscale x 16 x i1> %vb) {
; CHECK-LABEL: vmxnor_vv_nxv16i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m2, ta, mu
; CHECK-NEXT:    vmxnor.mm v0, v0, v8
; CHECK-NEXT:    ret
  %vc = xor <vscale x 16 x i1> %va, %vb
  %head = insertelement <vscale x 16 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 16 x i1> %head, <vscale x 16 x i1> poison, <vscale x 16 x i32> zeroinitializer
  %not = xor <vscale x 16 x i1> %vc, %splat
  ret <vscale x 16 x i1> %not
}

define <vscale x 1 x i1> @vmandn_vv_nxv1i1(<vscale x 1 x i1> %va, <vscale x 1 x i1> %vb) {
; CHECK-LABEL: vmandn_vv_nxv1i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf8, ta, mu
; CHECK-NEXT:    vmandn.mm v0, v0, v8
; CHECK-NEXT:    ret
  %head = insertelement <vscale x 1 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 1 x i1> %head, <vscale x 1 x i1> poison, <vscale x 1 x i32> zeroinitializer
  %not = xor <vscale x 1 x i1> %vb, %splat
  %vc = and <vscale x 1 x i1> %va, %not
  ret <vscale x 1 x i1> %vc
}

define <vscale x 2 x i1> @vmandn_vv_nxv2i1(<vscale x 2 x i1> %va, <vscale x 2 x i1> %vb) {
; CHECK-LABEL: vmandn_vv_nxv2i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf4, ta, mu
; CHECK-NEXT:    vmandn.mm v0, v0, v8
; CHECK-NEXT:    ret
  %head = insertelement <vscale x 2 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 2 x i1> %head, <vscale x 2 x i1> poison, <vscale x 2 x i32> zeroinitializer
  %not = xor <vscale x 2 x i1> %vb, %splat
  %vc = and <vscale x 2 x i1> %va, %not
  ret <vscale x 2 x i1> %vc
}

define <vscale x 4 x i1> @vmandn_vv_nxv4i1(<vscale x 4 x i1> %va, <vscale x 4 x i1> %vb) {
; CHECK-LABEL: vmandn_vv_nxv4i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf2, ta, mu
; CHECK-NEXT:    vmandn.mm v0, v0, v8
; CHECK-NEXT:    ret
  %head = insertelement <vscale x 4 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 4 x i1> %head, <vscale x 4 x i1> poison, <vscale x 4 x i32> zeroinitializer
  %not = xor <vscale x 4 x i1> %vb, %splat
  %vc = and <vscale x 4 x i1> %va, %not
  ret <vscale x 4 x i1> %vc
}

define <vscale x 8 x i1> @vmandn_vv_nxv8i1(<vscale x 8 x i1> %va, <vscale x 8 x i1> %vb) {
; CHECK-LABEL: vmandn_vv_nxv8i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m1, ta, mu
; CHECK-NEXT:    vmandn.mm v0, v0, v8
; CHECK-NEXT:    ret
  %head = insertelement <vscale x 8 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 8 x i1> %head, <vscale x 8 x i1> poison, <vscale x 8 x i32> zeroinitializer
  %not = xor <vscale x 8 x i1> %vb, %splat
  %vc = and <vscale x 8 x i1> %va, %not
  ret <vscale x 8 x i1> %vc
}

define <vscale x 16 x i1> @vmandn_vv_nxv16i1(<vscale x 16 x i1> %va, <vscale x 16 x i1> %vb) {
; CHECK-LABEL: vmandn_vv_nxv16i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m2, ta, mu
; CHECK-NEXT:    vmandn.mm v0, v0, v8
; CHECK-NEXT:    ret
  %head = insertelement <vscale x 16 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 16 x i1> %head, <vscale x 16 x i1> poison, <vscale x 16 x i32> zeroinitializer
  %not = xor <vscale x 16 x i1> %vb, %splat
  %vc = and <vscale x 16 x i1> %va, %not
  ret <vscale x 16 x i1> %vc
}

define <vscale x 1 x i1> @vmorn_vv_nxv1i1(<vscale x 1 x i1> %va, <vscale x 1 x i1> %vb) {
; CHECK-LABEL: vmorn_vv_nxv1i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf8, ta, mu
; CHECK-NEXT:    vmorn.mm v0, v0, v8
; CHECK-NEXT:    ret
  %head = insertelement <vscale x 1 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 1 x i1> %head, <vscale x 1 x i1> poison, <vscale x 1 x i32> zeroinitializer
  %not = xor <vscale x 1 x i1> %vb, %splat
  %vc = or <vscale x 1 x i1> %va, %not
  ret <vscale x 1 x i1> %vc
}

define <vscale x 2 x i1> @vmorn_vv_nxv2i1(<vscale x 2 x i1> %va, <vscale x 2 x i1> %vb) {
; CHECK-LABEL: vmorn_vv_nxv2i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf4, ta, mu
; CHECK-NEXT:    vmorn.mm v0, v0, v8
; CHECK-NEXT:    ret
  %head = insertelement <vscale x 2 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 2 x i1> %head, <vscale x 2 x i1> poison, <vscale x 2 x i32> zeroinitializer
  %not = xor <vscale x 2 x i1> %vb, %splat
  %vc = or <vscale x 2 x i1> %va, %not
  ret <vscale x 2 x i1> %vc
}

define <vscale x 4 x i1> @vmorn_vv_nxv4i1(<vscale x 4 x i1> %va, <vscale x 4 x i1> %vb) {
; CHECK-LABEL: vmorn_vv_nxv4i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, mf2, ta, mu
; CHECK-NEXT:    vmorn.mm v0, v0, v8
; CHECK-NEXT:    ret
  %head = insertelement <vscale x 4 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 4 x i1> %head, <vscale x 4 x i1> poison, <vscale x 4 x i32> zeroinitializer
  %not = xor <vscale x 4 x i1> %vb, %splat
  %vc = or <vscale x 4 x i1> %va, %not
  ret <vscale x 4 x i1> %vc
}

define <vscale x 8 x i1> @vmorn_vv_nxv8i1(<vscale x 8 x i1> %va, <vscale x 8 x i1> %vb) {
; CHECK-LABEL: vmorn_vv_nxv8i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m1, ta, mu
; CHECK-NEXT:    vmorn.mm v0, v0, v8
; CHECK-NEXT:    ret
  %head = insertelement <vscale x 8 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 8 x i1> %head, <vscale x 8 x i1> poison, <vscale x 8 x i32> zeroinitializer
  %not = xor <vscale x 8 x i1> %vb, %splat
  %vc = or <vscale x 8 x i1> %va, %not
  ret <vscale x 8 x i1> %vc
}

define <vscale x 16 x i1> @vmorn_vv_nxv16i1(<vscale x 16 x i1> %va, <vscale x 16 x i1> %vb) {
; CHECK-LABEL: vmorn_vv_nxv16i1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e8, m2, ta, mu
; CHECK-NEXT:    vmorn.mm v0, v0, v8
; CHECK-NEXT:    ret
  %head = insertelement <vscale x 16 x i1> poison, i1 1, i32 0
  %splat = shufflevector <vscale x 16 x i1> %head, <vscale x 16 x i1> poison, <vscale x 16 x i32> zeroinitializer
  %not = xor <vscale x 16 x i1> %vb, %splat
  %vc = or <vscale x 16 x i1> %va, %not
  ret <vscale x 16 x i1> %vc
}

