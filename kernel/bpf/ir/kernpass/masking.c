#include "linux/bpf_verifier.h"
#include "linux/stddef.h"
#include <linux/bpf_ir.h>
#include "../../ir_kern.h"

void masking_pass(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct bpf_verifier_env *venv = env->venv;
	if (!venv) {
		RAISE_ERROR("Empty verifier env");
	}
	struct bpf_verifier_state *curstate = venv->cur_state;
	PRINT_LOG(env, "Verifier stuck on insn: %d\n", venv->insn_idx);
	if (env->verifier_err == BPF_VERIFIER_ERR_303) {
		// math between map_value pointer and register with unbounded min value is not allowed
		struct bpf_reg_state *regs =
			curstate->frame[curstate->curframe]->regs;
		struct bpf_insn raw_insn = env->insns[venv->insn_idx];
		PRINT_LOG(env, "raw instruction dst: %d, src: %d\n",
			  raw_insn.dst_reg, raw_insn.src_reg);
		struct bpf_reg_state *dst = &regs[raw_insn.dst_reg];
		struct bpf_reg_state *src = &regs[raw_insn.src_reg];
		if (!(dst->type == PTR_TO_MAP_VALUE &&
		      src->type == SCALAR_VALUE)) {
			// Cannot apply
			return;
		}
		// Add check to src
		struct ir_insn *insn =
			bpf_ir_find_ir_insn_by_rawpos(fun, venv->insn_idx);
		if (!insn) {
			return;
		}
		// Found the IR instruction
		if (!bpf_ir_is_alu(insn)) {
			return;
		}
		// ALU v0 v1
		// v1 is srcq
		struct ir_raw_pos v1p = insn->values[1].raw_pos;
		if (!v1p.valid || insn->values[1].type != IR_VALUE_INSN) {
			return;
		}
		struct ir_basic_block *err_bb = bpf_ir_create_bb(env, fun);
		bpf_ir_create_ret_insn_bb(env, err_bb, bpf_ir_value_const32(1),
					  INSERT_BACK);
		struct ir_basic_block *old_bb = insn->parent_bb;
		// Split before insn
		struct ir_basic_block *new_bb =
			bpf_ir_split_bb(env, fun, insn, true);

		bpf_ir_create_jbin_insn_bb(env, old_bb, insn->values[1],
					   bpf_ir_value_const32(0), new_bb,
					   err_bb, IR_INSN_JGT, IR_ALU_64,
					   INSERT_BACK);
	}
	RAISE_ERROR("success");
}