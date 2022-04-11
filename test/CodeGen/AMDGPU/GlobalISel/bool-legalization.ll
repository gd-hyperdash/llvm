; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -global-isel -march=amdgcn -mcpu=hawaii -mattr=+flat-for-global -verify-machineinstrs < %s | FileCheck -check-prefix=GCN %s

; End to end tests for scalar vs. vector boolean legalization strategies.

define amdgpu_ps float @select_vgpr_sgpr_trunc_cond(i32 inreg %a, i32 %b, i32 %c) {
; GCN-LABEL: select_vgpr_sgpr_trunc_cond:
; GCN:       ; %bb.0:
; GCN-NEXT:    s_and_b32 s0, 1, s0
; GCN-NEXT:    v_cmp_ne_u32_e64 vcc, 0, s0
; GCN-NEXT:    v_cndmask_b32_e32 v0, v1, v0, vcc
; GCN-NEXT:    ; return to shader part epilog
  %cc = trunc i32 %a to i1
  %r = select i1 %cc, i32 %b, i32 %c
  %r.f = bitcast i32 %r to float
  ret float %r.f
}

define amdgpu_ps float @select_vgpr_sgpr_trunc_and_cond(i32 inreg %a.0, i32 inreg %a.1, i32 %b, i32 %c) {
; GCN-LABEL: select_vgpr_sgpr_trunc_and_cond:
; GCN:       ; %bb.0:
; GCN-NEXT:    s_and_b32 s0, s0, s1
; GCN-NEXT:    s_and_b32 s0, 1, s0
; GCN-NEXT:    v_cmp_ne_u32_e64 vcc, 0, s0
; GCN-NEXT:    v_cndmask_b32_e32 v0, v1, v0, vcc
; GCN-NEXT:    ; return to shader part epilog
  %cc.0 = trunc i32 %a.0 to i1
  %cc.1 = trunc i32 %a.1 to i1
  %and = and i1 %cc.0, %cc.1
  %r = select i1 %and, i32 %b, i32 %c
  %r.f = bitcast i32 %r to float
  ret float %r.f
}

define amdgpu_ps i32 @select_sgpr_trunc_and_cond(i32 inreg %a.0, i32 inreg %a.1, i32 inreg %b, i32 inreg %c) {
; GCN-LABEL: select_sgpr_trunc_and_cond:
; GCN:       ; %bb.0:
; GCN-NEXT:    s_and_b32 s0, s0, s1
; GCN-NEXT:    s_and_b32 s0, s0, 1
; GCN-NEXT:    s_cmp_lg_u32 s0, 0
; GCN-NEXT:    s_cselect_b32 s0, s2, s3
; GCN-NEXT:    ; return to shader part epilog
  %cc.0 = trunc i32 %a.0 to i1
  %cc.1 = trunc i32 %a.1 to i1
  %and = and i1 %cc.0, %cc.1
  %r = select i1 %and, i32 %b, i32 %c
  ret i32 %r
}

define amdgpu_kernel void @sgpr_trunc_brcond(i32 %cond) {
; GCN-LABEL: sgpr_trunc_brcond:
; GCN:       ; %bb.0: ; %entry
; GCN-NEXT:    s_load_dword s0, s[0:1], 0x9
; GCN-NEXT:    s_waitcnt lgkmcnt(0)
; GCN-NEXT:    s_xor_b32 s0, s0, -1
; GCN-NEXT:    s_and_b32 s0, s0, 1
; GCN-NEXT:    s_cmp_lg_u32 s0, 0
; GCN-NEXT:    s_cbranch_scc1 .LBB3_2
; GCN-NEXT:  ; %bb.1: ; %bb0
; GCN-NEXT:    v_mov_b32_e32 v0, 0
; GCN-NEXT:    flat_store_dword v[0:1], v0
; GCN-NEXT:    s_waitcnt vmcnt(0)
; GCN-NEXT:  .LBB3_2: ; %bb1
; GCN-NEXT:    v_mov_b32_e32 v0, 1
; GCN-NEXT:    flat_store_dword v[0:1], v0
; GCN-NEXT:    s_waitcnt vmcnt(0)
entry:
  %trunc = trunc i32 %cond to i1
  br i1 %trunc, label %bb0, label %bb1

bb0:
  store volatile i32 0, i32 addrspace(1)* undef
  unreachable

bb1:
  store volatile i32 1, i32 addrspace(1)* undef
  unreachable
}

define amdgpu_kernel void @brcond_sgpr_trunc_and(i32 %cond0, i32 %cond1) {
; GCN-LABEL: brcond_sgpr_trunc_and:
; GCN:       ; %bb.0: ; %entry
; GCN-NEXT:    s_load_dwordx2 s[0:1], s[0:1], 0x9
; GCN-NEXT:    s_waitcnt lgkmcnt(0)
; GCN-NEXT:    s_and_b32 s0, s0, s1
; GCN-NEXT:    s_xor_b32 s0, s0, -1
; GCN-NEXT:    s_and_b32 s0, s0, 1
; GCN-NEXT:    s_cmp_lg_u32 s0, 0
; GCN-NEXT:    s_cbranch_scc1 .LBB4_2
; GCN-NEXT:  ; %bb.1: ; %bb0
; GCN-NEXT:    v_mov_b32_e32 v0, 0
; GCN-NEXT:    flat_store_dword v[0:1], v0
; GCN-NEXT:    s_waitcnt vmcnt(0)
; GCN-NEXT:  .LBB4_2: ; %bb1
; GCN-NEXT:    v_mov_b32_e32 v0, 1
; GCN-NEXT:    flat_store_dword v[0:1], v0
; GCN-NEXT:    s_waitcnt vmcnt(0)
entry:
  %trunc0 = trunc i32 %cond0 to i1
  %trunc1 = trunc i32 %cond1 to i1
  %and = and i1 %trunc0, %trunc1
  br i1 %and, label %bb0, label %bb1

bb0:
  store volatile i32 0, i32 addrspace(1)* undef
  unreachable

bb1:
  store volatile i32 1, i32 addrspace(1)* undef
  unreachable
}
