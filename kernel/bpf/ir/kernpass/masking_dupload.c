// SPDX-License-Identifier: GPL-2.0-only
#include "linux/bpf_common.h"
#include "linux/bpf_verifier.h"
#include "linux/stddef.h"
#include <linux/bpf_ir.h>
#include "../../ir_kern.h"

#define CHECK_COND(cond) \
	if (!(cond)) {   \
		return;  \
	}

static void masking_pass(struct bpf_ir_env *env, struct ir_function *fun,
			 void *param)
{
	struct bpf_verifier_env *venv = env->venv;
	if (!venv) {
		RAISE_ERROR("Empty verifier env");
	}
	struct bpf_verifier_state *curstate = venv->cur_state;
	PRINT_LOG_INFO(env, "Verifier stuck on insn: %d\n", venv->insn_idx);
	if (env->verifier_err >= BPF_VERIFIER_ERR_41 &&
	    env->verifier_err <= BPF_VERIFIER_ERR_44) {
		// memory range error
		// Should be a load/store instruction
		struct bpf_reg_state *regs =
			curstate->frame[curstate->curframe]->regs;
		struct bpf_insn raw_insn = env->insns[venv->insn_idx];
		PRINT_LOG_INFO(env, "raw instruction dst: %d, src: %d\n",
			  raw_insn.dst_reg, raw_insn.src_reg);
		struct bpf_reg_state *src = &regs[raw_insn.src_reg];
		CHECK_COND(src->type == PTR_TO_MAP_VALUE);
		PRINT_LOG_INFO(env, "array size %d\n", src->map_ptr->value_size);
		if (BPF_CLASS(raw_insn.code) == BPF_LDX &&
		    BPF_MODE(raw_insn.code) == BPF_MEM) {
			// Regular load
			// Add check to src
			struct ir_insn *insn = bpf_ir_find_ir_insn_by_rawpos(
				fun, venv->insn_idx);
			CHECK_COND(insn);
			// Found the IR instruction
			CHECK_COND(insn->op == IR_INSN_LOADRAW)
			// LOADRAW src
			struct ir_value v = insn->addr_val.value;

			CHECK_COND(v.type == IR_VALUE_INSN);
			struct ir_insn *aluinsn = v.data.insn_d;
			CHECK_COND(bpf_ir_is_bin_alu(aluinsn));
			struct ir_value index;

			if (aluinsn->values[0].data.insn_d->op ==
			    IR_INSN_LOADIMM_EXTRA) {
				index = aluinsn->values[1];
			} else if (aluinsn->values[1].data.insn_d->op ==
				   IR_INSN_LOADIMM_EXTRA) {
				index = aluinsn->values[0];
			} else {
				return;
			}
			struct ir_basic_block *err_bb =
				bpf_ir_create_bb(env, fun);
			bpf_ir_create_ret_insn_bb(env, err_bb,
						  bpf_ir_value_const32(1),
						  INSERT_BACK);
			struct ir_basic_block *old_bb = aluinsn->parent_bb;
			// Split before insn
			struct ir_basic_block *new_bb =
				bpf_ir_split_bb(env, fun, aluinsn, true);

			u32 max_num = src->map_ptr->value_size -
				      bpf_ir_sizeof_vr_type(
					      insn->vr_type); // +1 will error!

			bpf_ir_create_jbin_insn_bb(
				env, old_bb, index,
				bpf_ir_value_const32(max_num), new_bb, err_bb,
				IR_INSN_JGT, IR_ALU_64, INSERT_BACK);

			bpf_ir_connect_bb(env, old_bb, err_bb);
		}
	}
}

static bool check_run(int err)
{
	return err >= BPF_VERIFIER_ERR_41 && err <= BPF_VERIFIER_ERR_44;
}

const struct custom_pass_cfg bpf_ir_kern_masking_pass =
	DEF_CUSTOM_PASS(DEF_FUNC_PASS(masking_pass, "masking_dupload", false),
			check_run, NULL, NULL);
