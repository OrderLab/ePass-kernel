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

// Check if can fix the error
bool bpf_ir_canfix(struct bpf_ir_env *env)
{
	int err = env->verifier_err;

	for (size_t i = 0; i < env->opts.custom_pass_num; ++i) {
		if (env->opts.custom_passes[i].pass.enabled &&
		    env->opts.custom_passes[i].check_apply &&
		    env->opts.custom_passes[i].check_apply(err)) {
			return true;
		}
	}
	return false;
}

static bool has_any_enable_builtin(struct bpf_ir_env *env)
{
	for (size_t i = 0; i < env->opts.builtin_pass_cfg_num; ++i) {
		if (env->opts.builtin_pass_cfg[i].enable_cfg) {
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

static int reload_insns(struct bpf_prog **prog_ptr, struct bpf_ir_env *env)
{
	struct bpf_prog *prog = *prog_ptr;
	prog = bpf_prog_realloc(prog, bpf_prog_size(env->insn_cnt), GFP_USER);

	if (!prog) {
		return -ENOMEM;
	}
	*prog_ptr = prog;
	memcpy(prog->insnsi, env->insns,
	       env->insn_cnt * sizeof(struct bpf_insn));
	prog->len = env->insn_cnt;
	return 0;
}

static void init_vi_map(struct bpf_ir_env *env)
{
	// the insn number must be ready in env
	size_t cnt = env->insn_cnt;
	env->verifier_info_map = malloc_proto(cnt * sizeof(struct vi_entry));
	// Initialize the map
	for (size_t i = 0; i < cnt; ++i) {
		get_vi_entry(env, i)->valid = false;
	}
}

struct vi_entry *get_vi_entry(struct bpf_ir_env *env, u32 insn_idx)
{
	if (!env->verifier_info_map) {
		CRITICAL("Should not call get_vi_entry without checking NULL");
	}
	struct vi_entry *vi_map = env->verifier_info_map;
	return &vi_map[insn_idx];
}

static void free_vi_map(struct bpf_ir_env *env)
{
	free_proto(env->verifier_info_map);
	env->verifier_info_map = NULL;
}

static void print_log_to_ubuf(union bpf_attr *attr, struct bpf_ir_env *env)
{
	env->log[env->log_pos] = 0;
	char *ubuf = (char __user *)(unsigned long)attr->log_buf;
	if (copy_to_user(ubuf, env->log, env->log_pos + 1)) {
		env->err = -EINVAL;
	}
}

int bpf_ir_kern_run(struct bpf_prog **prog_ptr, union bpf_attr *attr,
		    bpfptr_t uattr, u32 uattr_size, const char *pass_opt,
		    const char *global_opt)
{
	u64 start_time = ktime_get_ns();
	enum bpf_prog_type type = attr->prog_type;
	int err = 0;
	struct bpf_prog *prog = *prog_ptr;
	// if (type == BPF_PROG_TYPE_SOCKET_FILTER) {
	// 	return bpf_check(prog_ptr, attr, uattr, uattr_size, NULL);
	// }

	struct bpf_ir_opts opts = bpf_ir_default_opts();

	// Initialize

	struct custom_pass_cfg custom_passes[] = { bpf_ir_kern_masking_pass };

	opts.custom_passes = custom_passes;
	opts.custom_pass_num = sizeof(custom_passes) / sizeof(custom_passes[0]);

	struct builtin_pass_cfg builtin_pass_cfgs[] = {
		bpf_ir_kern_insn_counter_pass, bpf_ir_kern_optimization_pass,
		bpf_ir_kern_msan, bpf_ir_kern_div_by_zero_pass,
		bpf_ir_kern_compaction_pass, bpf_ir_kern_pointer_check,
	};

	opts.builtin_pass_cfg = builtin_pass_cfgs;
	opts.builtin_pass_cfg_num =
		sizeof(builtin_pass_cfgs) / sizeof(builtin_pass_cfgs[0]);

	struct bpf_ir_env *env = bpf_ir_init_env(opts, prog->insnsi, prog->len);

	if (!env) {
		return -ENOMEM;
	}

	env->prog_type = type;

	// Feed the options
	err = bpf_ir_init_opts(env, global_opt, pass_opt);
	if (err) {
		goto clean_op;
	}

	if (env->opts.enable_printk_log) {
		printk("ePass enabled, program type: %d", type);
	}

	// Remove line info, otherwise the verifier will complain about that they cannot find those lines
	// (Also you could remove debug flag when compile ebpf programs)
	// printk("LINEINFO %u, %u", attr->line_info_cnt,
	//        attr->line_info_rec_size);
	attr->line_info_cnt = 0;

	if (env->opts.verbose > 3 && env->opts.enable_printk_log) {
		print_insns_log(env->insns, env->insn_cnt);
	}

	// Iteration

	u32 iter = 0;

	for (;;) {
		iter++;
		if (iter > env->opts.max_iteration) {
			err = -ELOOP;
			break;
		}

		// Clean Env
		bpf_ir_reset_env(env); // Will not clean opts & insns

		init_vi_map(env);
		err = bpf_check(prog_ptr, attr, uattr, uattr_size, env);

		if (err == 0) {
			// Pass the verifier
			break;
		}

		// Not pass the verifier

		if (!env->executed) {
			// Not even executed, cannot fix, abort!
			break;
		}

		// ePass executed

		// ePass Log
		if (env->opts.enable_printk_log) {
			bpf_ir_print_log_dbg(env);
		}

		if (env->err) {
			// Unrecoverable error
			if (env->opts.enable_printk_log) {
				printk("ePass failed: %d", env->err);
			}
			break;
		}

		// ePass successfully generate new code

		err = reload_insns(prog_ptr, env);
		free_vi_map(env);
		if (err) {
			break;
		}
	}

	if (err) {
		goto clean_op;
	}

	// Make sure the verifier informatio is ready
	if (!env->verifier_info_map) {
		if (env->opts.enable_printk_log) {
			printk("Verifier not ready!");
		}
		goto clean_op;
	}

	// Debug: test the VI map
	for (size_t i = 0; i < env->insn_cnt; ++i) {
		struct vi_entry *entry = get_vi_entry(env, i);
		if (entry->valid) {
			if (env->opts.enable_printk_log) {
				printk("VI[%zu]: valid. src type: %d dst type: %d", i, entry->src_reg_state.type, entry->dst_reg_state.type);
			}
		}
	}


	// Run built-in passes
	if (has_any_enable_builtin(env) || env->opts.force) {
		enable_builtin(env);
		bpf_ir_reset_env(env);

		bpf_ir_autorun(env);
		if (env->err) {
			if (env->opts.enable_printk_log) {
				bpf_ir_print_log_dbg(env);
				printk("Builtin pass failed: %d", env->err);
			}
			print_log_to_ubuf(attr, env);
			// Unrecoverable error
			err = env->err;
			goto clean_op;
		}

		// Successfully run the built-in passes

		err = reload_insns(prog_ptr, env);
		if (err) {
			goto clean_op;
		}

		// Free VI map
		free_vi_map(env);

		// Run the verifier the last time to check if the program is valid
		err = bpf_check(prog_ptr, attr, uattr, uattr_size, env);

		if (err) {
			// Not pass the verifier, abort
			if (env->opts.enable_printk_log) {
				printk("Builtin pass failed to pass the verifier: %d",
				       err);
				bpf_ir_print_log_dbg(env);
				print_insns_log(env->insns, env->insn_cnt);
			}
			goto clean_op;
		}
		// Successfully pass the verifier
		if (env->opts.verbose > 3 && env->opts.enable_printk_log) {
			print_insns_log(env->insns, env->insn_cnt);
		}
	}

	// Success
	u64 tot_time = ktime_get_ns() - start_time;
	PRINT_LOG_DEBUG(
		env,
		"ePass Result:\nTotal time: %lluns, ePass time: %lluns (%lluns, %lluns, %lluns)\n",
		tot_time, env->lift_time + env->run_time + env->cg_time,
		env->lift_time, env->run_time, env->cg_time);
	print_log_to_ubuf(attr, env);

clean_op:
	bpf_ir_free_opts(env);
	bpf_ir_free_env(env);
	if (env->verifier_info_map) {
		free_vi_map(env);
	}
	return err;
}
