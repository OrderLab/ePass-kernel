// SPDX-License-Identifier: GPL-2.0-only
#include "linux/bpf_common.h"
#include "linux/bpf_verifier.h"
#include "linux/stddef.h"
#include <linux/bpf_ir.h>
#include "../../ir_kern.h"

// 64-bit null pointer
#define NULL_PTR bpf_ir_value_const64(0)

// TODO: move from bpf_ir.c to bpf_ir.h
static const s8 helper_func_arg_num[] = {
	[1] = 2, // map_lookup_elem
	[2] = 4, // map_update_elem
	[3] = 2, // map_delete_elem
	[4] = 3, // bpf_probe_read
	[5] = 0, // ktime_get_ns
	[6] = -1, // trace_printk // 5 may cause an error. May not have 5 arguments
	[7] = 0, // get_prandom_u32
	[8] = 0, // get_smp_processor_id
	[9] = 5, // skb_store_bytes
	[10] = 5, // l3_csum_replace
	[11] = 5, // l4_csum_replace
	[12] = 3, // tail_call
	[13] = 3, // clone_redirect
	[14] = 0, // get_current_pid_tgid
	[15] = 0, // get_current_uid_gid
	[16] = 2, // get_current_comm
	[17] = 1, // get_cgroup_classid
	[18] = 3, // skb_vlan_push
	[19] = 1, // skb_vlan_pop
	[20] = 4, // skb_get_tunnel_key
	[21] = 4, // skb_set_tunnel_key
	[22] = 2, // perf_event_read
	[23] = 2, // redirect
	[24] = 1, // get_route_realm
	[25] = 5, // perf_event_output
	[26] = 4, // skb_load_bytes
	[27] = 3, // get_stackid
	[28] = 5, // csum_diff
	[29] = 3, // skb_get_tunnel_opt
	[30] = 3, // skb_set_tunnel_opt
	[31] = 3, // skb_change_proto
	[32] = 2, // skb_change_type
	[33] = 3, // skb_under_cgroup
	[34] = 1, // get_hash_recalc
	[35] = 0, // get_current_task
	[36] = 3, // probe_write_user
	[37] = 2, // current_task_under_cgroup
	[38] = 3, // skb_change_tail
	[39] = 2, // skb_pull_data
	[40] = 2, // csum_update
	[41] = 1, // set_hash_invalid
	[42] = 0, // get_numa_node_id
	[43] = 3, // skb_change_head
	[44] = 2, // xdp_adjust_head
	[45] = 3, // bpf_probe_read_str
	[46] = 1, // get_socket_cookie
	[47] = 1, // get_socket_uid
	[48] = 2, // set_hash
	[49] = 5, // setsockopt
	[50] = 4, // skb_adjust_room
	[51] = 3, // bpf_redirect_map
	[52] = 4, // sk_redirect_map
	[53] = 4, // sock_map_update
	[54] = 2, // xdp_adjust_meta
	[55] = 4, // perf_event_read_value
	[56] = 3, // perf_prog_read_value
	[57] = 5, // getsockopt
	[58] = 2, // override_return
	[59] = 2, // sock_ops_cb_flags_set
	[60] = 4, // msg_redirect_map
	[61] = 2, // msg_apply_bytes
	[62] = 2, // msg_cork_bytes
	[63] = 4, // msg_pull_data
	[64] = 3, // bind
	[65] = 2, // xdp_adjust_tail
	[66] = 5, // skb_get_xfrm_state
	[67] = 4, // get_stack
	[68] = 5, // skb_load_bytes_relative
	[69] = 4, // fib_lookup
	[70] = 4, // sock_hash_update
	[71] = 4, // msg_redirect_hash
	[72] = 4, // sk_redirect_hash
	[73] = 4, // lwt_push_encap
	[74] = 4, // lwt_seg6_store_bytes
	[75] = 3, // lwt_seg6_adjust_srh
	[76] = 4, // lwt_seg6_action
	[77] = 1, // rc_repeat
	[78] = 4, // rc_keydown
	[79] = 1, // skb_cgroup_id
	[80] = 0, // get_current_cgroup_id
	[81] = 2, // get_local_storage
	[82] = 4, // sk_select_reuseport
	[83] = 2, // skb_ancestor_cgroup_id
	[84] = 5, // sk_lookup_tcp
	[85] = 5, // sk_lookup_udp
	[86] = 1, // sk_release
	[87] = 3, // map_push_elem
	[88] = 2, // map_pop_elem
	[89] = 2, // map_peek_elem
	[90] = 4, // msg_push_data
	[91] = 4, // msg_pop_data
	[92] = 3, // rc_pointer_rel
	[93] = 1, // spin_lock
	[94] = 1, // spin_unlock
	[95] = 1, // sk_fullsock
	[96] = 1, // tcp_sock
	[97] = 1, // skb_ecn_set_ce
	[98] = 1, // get_listener_sock
	[99] = 5, // skc_lookup_tcp
	[100] = 5, // tcp_check_syncookie
	[101] = 4, // sysctl_get_name
	[102] = 3, // sysctl_get_current_value
	[103] = 3, // sysctl_get_new_value
	[104] = 3, // sysctl_set_new_value
	[105] = 4, // strtol
	[106] = 4, // strtoul
	[107] = 5, // sk_storage_get
	[108] = 2, // sk_storage_delete
	[109] = 1, // send_signal
	[110] = 5, // tcp_gen_syncookie
	[111] = 5, // skb_output
	[112] = 3, // probe_read_user
	[113] = 3, // probe_read_kernel
	[114] = 3, // probe_read_user_str
	[115] = 3, // probe_read_kernel_str
	[116] = 2, // tcp_send_ack
	[117] = 1, // send_signal_thread
	[118] = 0, // jiffies64
	[119] = 4, // read_branch_records
	[120] = 4, // get_ns_current_pid_tgid
	[121] = 5, // xdp_output
	[122] = 1, // get_netns_cookie
	[123] = 1, // get_current_ancestor_cgroup_id
	[124] = 3, // sk_assign
	[125] = 0, // ktime_get_boot_ns
	[126] = 5, // seq_printf
	[127] = 3, // seq_write
	[128] = 1, // sk_cgroup_id
	[129] = 2, // sk_ancestor_cgroup_id
	[130] = 4, // ringbuf_output
	[131] = 3, // ringbuf_reserve
	[132] = 2, // ringbuf_submit
	[133] = 2, // ringbuf_discard
	[134] = 2, // ringbuf_query
	[135] = 2, // csum_level
	[136] = 1, // skc_to_tcp6_sock
	[137] = 1, // skc_to_tcp_sock
	[138] = 1, // skc_to_tcp_timewait_sock
	[139] = 1, // skc_to_tcp_request_sock
	[140] = 1, // skc_to_udp6_sock
	[141] = 4, // get_task_stack
	[142] = 4, // load_hdr_opt
	[143] = 4, // store_hdr_opt
	[144] = 3, // reserve_hdr_opt
	[145] = 5, // inode_storage_get
	[146] = 2, // inode_storage_delete
	[147] = 3, // d_path
	[148] = 3, // copy_from_user
	[149] = 5, // snprintf_btf
	[150] = 4, // seq_printf_btf
	[151] = 1, // skb_cgroup_classid
	[152] = 4, // redirect_neigh
	[153] = 2, // per_cpu_ptr
	[154] = 1, // this_cpu_ptr
	[155] = 2, // redirect_peer
	[156] = 5, // task_storage_get
	[157] = 2, // task_storage_delete
	[158] = 0, // get_current_task_btf
	[159] = 2, // bprm_opts_set
	[160] = 0, // ktime_get_coarse_ns
	[161] = 3, // ima_inode_hash
	[162] = 1, // sock_from_file
	[163] = 5, // check_mtu
	[164] = 4, // for_each_map_elem
	[165] = 5, // snprintf
	[166] = 3, // sys_bpf
	[167] = 4, // btf_find_by_name_kind
	[168] = 1, // sys_close
	[169] = 3, // timer_init
	[170] = 3, // timer_set_callback
	[171] = 3, // timer_start
	[172] = 1, // timer_cancel
	[173] = 1, // get_func_ip
	[174] = 1, // get_attach_cookie
	[175] = 1, // task_pt_regs
	[176] = 3, // get_branch_snapshot
	[177] = 4, // trace_vprintk
	[178] = 1, // skc_to_unix_sock
	[179] = 4, // kallsyms_lookup_name
	[180] = 5, // find_vma
	[181] = 4, // loop
	[182] = 3, // strncmp
	[183] = 3, // get_func_arg
	[184] = 2, // bpf_get_func_ret
	[185] = 1, // bpf_get_func_arg_cnt
	[186] = 0, // get_retval
	[187] = 1, // set_retval
	[188] = 1, // xdp_get_buff_len
	[189] = 4, // xdp_load_bytes
	[190] = 4, // xdp_store_bytes
	[191] = 5, // copy_from_user_task
	[192] = 3, // skb_set_tstamp
	[193] = 3, // ima_file_hash
	[194] = 2, // kptr_xchg
	[195] = 3, // map_lookup_percpu_elem
	[196] = 1, // skc_to_mptcp_sock
	[197] = 4, // dynptr_from_mem
	[198] = 4, // ringbuf_reserve_dynptr
	[199] = 2, // ringbuf_submit_dynptr
	[200] = 2, // ringbuf_discard_dynptr
	[201] = 5, // dynptr_read
	[202] = 5, // dynptr_write
	[203] = 3, // dynptr_data
	[204] = 3, // tcp_raw_gen_syncookie_ipv4
	[205] = 3, // tcp_raw_gen_syncookie_ipv6
	[206] = 2, // tcp_raw_check_syncookie_ipv4
	[207] = 2, // tcp_raw_check_syncookie_ipv6
	[208] = 0, // ktime_get_tai_ns
	[209] = 4, // user_ringbuf_drain
	[210] = 5, // cgrp_storage_get
	[211] = 2, // cgrp_storage_delete
};

static void alu_check(struct bpf_ir_env *env, struct ir_function *fun,
						struct ir_insn *insn)
{
	// Skipped static check for bpf_reg_state (enforced by verifier)
	// - Both dst and src are pointers is not allowed
	// - src is a pointer is not allowed
	struct ir_insn *prev = bpf_ir_prev_insn(insn);
	struct ir_basic_block *bb = insn->parent_bb;
	if (!prev) {
		return;
	}
	struct ir_basic_block *new_bb =
		bpf_ir_split_bb(env, fun, prev, INSERT_BACK);
	struct ir_basic_block *err_bb =
		bpf_ir_create_bb(env, fun);
	bpf_ir_create_throw_insn_bb(env, err_bb, INSERT_BACK);

	// *_OR_NULL pointer cannot be used in ALU  
	struct vi_entry *entry = get_vi_entry(env, insn->_insn_id);
	struct bpf_reg_state *dst_reg = &entry->dst_reg_state;
	if (dst_reg->type != SCALAR_VALUE) {
		bpf_ir_create_jbin_insn(
					env, prev, insn->values[0], 
					NULL_PTR, new_bb, err_bb, 
					IR_INSN_JEQ, IR_ALU_64, INSERT_BACK);
		// Manually connect BBs
		bpf_ir_connect_bb(env, bb, err_bb);
	}
}

static void helper_check(struct bpf_ir_env *env, struct ir_function *fun,
						struct ir_insn *insn)
{
	struct vi_entry *entry = get_vi_entry(env, insn->_insn_id);
	struct bpf_reg_state *arg_regs = entry->arg_reg_states;
	
	struct ir_insn *prev = bpf_ir_prev_insn(insn);
	struct ir_basic_block *bb = insn->parent_bb;
	if (!prev) {
		return;
	}

	struct ir_basic_block *new_bb =
		bpf_ir_split_bb(env, fun, prev, INSERT_BACK);
	struct ir_basic_block *err_bb =
		bpf_ir_create_bb(env, fun);
	bpf_ir_create_throw_insn_bb(env, err_bb, INSERT_BACK);

	for (int i = 0; i < helper_func_arg_num[insn->fid]; i++) {
		if (arg_regs[i].type != SCALAR_VALUE) {
			// val == nullptr -> err
			struct ir_insn *null_check_insn = bpf_ir_create_jbin_insn(env, prev, 
							insn->values[i], NULL_PTR, new_bb, err_bb, 
							IR_INSN_JEQ, IR_ALU_64, INSERT_BACK);
			// val > umax -> err
			struct ir_insn *max_check_insn = bpf_ir_create_jbin_insn(env, null_check_insn,
							insn->values[i], bpf_ir_value_const64(arg_regs[i].umax_value), new_bb, err_bb,
							IR_INSN_JGT, IR_ALU_64, INSERT_BACK);
			// val < umin -> err
			bpf_ir_create_jbin_insn(env, max_check_insn,
							insn->values[i], bpf_ir_value_const64(arg_regs[i].umin_value), new_bb, err_bb,
							IR_INSN_JLT, IR_ALU_64, INSERT_BACK);
		}
	}
	// Manually connect BBs
	bpf_ir_connect_bb(env, bb, err_bb);
}

static void pointer_check(struct bpf_ir_env *env, struct ir_function *fun,
			 void *param)
{
	struct bpf_verifier_env *venv = env->venv;
	if (!venv) {
		RAISE_ERROR("Empty verifier env");
	}

	struct array call_insns;
	INIT_ARRAY(&call_insns, struct ir_insn *);
	struct array alu_insns;
	INIT_ARRAY(&alu_insns, struct ir_insn *);

	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_CALL) {
				bpf_ir_array_push(env, &call_insns, &insn);
			} else if (bpf_ir_is_bin_alu(insn)) {
				bpf_ir_array_push(env, &alu_insns, &insn);
			}
		}
	}

	struct ir_insn **pos2;
	array_for(pos2, alu_insns)
	{
		struct ir_insn *insn = *pos2;
		alu_check(env, fun, insn);
	}

	array_for(pos2, call_insns)
	{
		struct ir_insn *insn = *pos2;
		helper_check(env, fun, insn);
	}

	bpf_ir_array_free(&call_insns);
	bpf_ir_array_free(&alu_insns);
}

static bool check_run(int err)
{
	return true;
}

const struct custom_pass_cfg bpf_ir_kern_pointer_check =
	DEF_CUSTOM_PASS(DEF_FUNC_PASS(pointer_check, "pointer_check", false),
			check_run, NULL, NULL);