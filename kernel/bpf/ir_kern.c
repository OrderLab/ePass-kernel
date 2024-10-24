// SPDX-License-Identifier: GPL-2.0-only
// bpf_ir kernel functions

#include "ir_kern.h"
#include "linux/bpf_ir.h"
#include "linux/bpf.h"

static void print_insns_log(struct bpf_insn *insns, u32 len)
{
	printk("Program size: %d", len);
	for (u32 i = 0; i < len; ++i) {
		struct bpf_insn *insn = &insns[i];
		__u64 data;
		memcpy(&data, insn, sizeof(struct bpf_insn));
		printk("insn[%d]: %llu\n", i, data);
	}
}

static inline unsigned int bpf_prog_size(unsigned int proglen)
{
	return max(sizeof(struct bpf_prog),
		   offsetof(struct bpf_prog, insns[proglen]));
}

// Check if can fix the error
bool bpf_ir_canfix(struct bpf_ir_env *env)
{
	int err = env->verifier_err;

	for (size_t i = 0; i < env->opts.custom_pass_num; ++i) {
		if (env->opts.custom_passes[i].check_apply &&
		    env->opts.custom_passes[i].check_apply(err)) {
			return true;
		}
	}
	return false;
}

// Enable all builtin passes specified by enable_cfg
static void enable_builtin(struct bpf_ir_env *env)
{
	for (size_t i = 0; i < env->opts.builtin_pass_cfg_num; ++i) {
		if (env->opts.builtin_pass_cfg[i].enable_cfg) {
			env->opts.builtin_pass_cfg[i].enable = true;
		}
	}
}

int bpf_ir_kern_run(struct bpf_prog **prog_ptr, union bpf_attr *attr,
		    bpfptr_t uattr, u32 uattr_size, const char *pass_opt,
		    const char *global_opt)
{
	enum bpf_prog_type type = attr->prog_type;
	int err = 0;
	struct bpf_prog *prog = *prog_ptr;
	printk("Program type: %d", type);
	if (type == BPF_PROG_TYPE_SOCKET_FILTER) {
		// Filter program, do not run the framework
		return bpf_check(prog_ptr, attr, uattr, uattr_size, NULL);
	}
	// TODO: Check if the program is offloaded to the hardware
	// If not, do no run the pipeline

	print_insns_log(prog->insnsi, prog->len);

	struct bpf_ir_opts opts = bpf_ir_default_opts();

	// Initialize

	struct custom_pass_cfg custom_passes[] = { bpf_ir_kern_masking_pass };

	opts.custom_passes = custom_passes;
	opts.custom_pass_num = sizeof(custom_passes) / sizeof(custom_passes[0]);

	struct builtin_pass_cfg builtin_pass_cfgs[] = {
		bpf_ir_kern_add_counter_pass
	};

	opts.builtin_pass_cfg = builtin_pass_cfgs;
	opts.builtin_pass_cfg_num =
		sizeof(builtin_pass_cfgs) / sizeof(builtin_pass_cfgs[0]);

	struct bpf_ir_env *env = bpf_ir_init_env(opts, prog->insnsi, prog->len);

	if (!env) {
		return -ENOMEM;
	}

	// Feed the options
	err = bpf_ir_init_opts(env, pass_opt, global_opt);
	if (err) {
		goto clean_op;
	}

	// Remove line info, otherwise the verifier will complain about that they cannot find those lines
	// (Also you could remove debug flag when compile ebpf programs)
	// printk("LINEINFO %u, %u", attr->line_info_cnt,
	//        attr->line_info_rec_size);
	attr->line_info_cnt = 0;

	// Iteration

	u32 iter = 0;

	while (true) {
		iter++;
		if (iter >= env->opts.max_iteration) {
			err = -ELOOP;
			break;
		}
	}

	if (err) {
		goto clean_op;
	}

	// Run built-in passes

	/*
		err = bpf_check(prog_ptr, attr, uattr, uattr_size, env);
		if (err) {
			// Error
			// Check if the error code could be resolved using the framework

			// print_insns_log(prog->insnsi, prog->len);

			bpf_ir_print_log_dbg(env);

			printk("Pipeline done, return code: %d", env->err);
			if (env->err) {
				bpf_ir_free_env(env);
				return err;
			}
			// print_insns_log(env->insns, env->insn_cnt);

			// Use new insns
			prog = bpf_prog_realloc(
				prog, bpf_prog_size(env->insn_cnt), GFP_USER);

			printk("Prog realloc done with return code: %d", err);
			if (!prog) {
				bpf_ir_free_env(env);
				return -ENOMEM;
			}
			*prog_ptr = prog;
			memcpy(prog->insnsi, env->insns,
			       env->insn_cnt * sizeof(struct bpf_insn));
			prog->len = env->insn_cnt;

			// Remove line info, otherwise the verifier will complain about that they cannot find those lines
			// (Also you could remove debug flag when compile ebpf programs)
			// printk("LINEINFO %u, %u", attr->line_info_cnt,
			//        attr->line_info_rec_size);
			attr->line_info_cnt = 0;
			err = bpf_check(prog_ptr, attr, uattr, uattr_size, env);
			if (err) {
				// TODO
				printk("Verifier second time error: %d", err);
				bpf_ir_free_env(env);
				return err;
			} else {
				printk("Verifier second time success!");
			}
		}
	*/
clean_op:
	bpf_ir_free_opts(env);
	bpf_ir_free_env(env);
	return err;
}
