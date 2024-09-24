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

int bpf_ir_kern_run(struct bpf_prog **prog_ptr, union bpf_attr *attr,
		    bpfptr_t uattr, u32 uattr_size)
{
	enum bpf_prog_type type = attr->prog_type;
	int err = 0;
	struct bpf_prog *prog = *prog_ptr;
	printk("Program type: %d", type);
	if (type != BPF_PROG_TYPE_SOCKET_FILTER) {
		// TODO: Check if the program is offloaded to the hardware
		// If not, do no run the pipeline

		print_insns_log(prog->insnsi, prog->len);

		struct bpf_ir_opts opts = {
			.debug = 1,
			.print_mode = BPF_IR_PRINT_BPF,
		};
		struct bpf_ir_env *env = bpf_ir_init_env(opts);
		if (!env) {
			return -ENOMEM;
		}

		// Call the verifier

		err = bpf_check(prog_ptr, attr, uattr, uattr_size, env);
		if (err) {
			// Error
			// Check if the error code could be resolved using the framework

			print_insns_log(prog->insnsi, prog->len);

			// TODO

			bpf_ir_run(env, prog->insnsi, prog->len);
			if (env->err) {
				return env->err;
			}
			bpf_ir_print_log_dbg(env);
			printk("Pipeline done, return code: %d", err);
			print_insns_log(env->insns, env->insn_cnt);
			if (err < 0)
				return err;

			/* Kernel Start */
			prog = bpf_prog_realloc(
				prog, bpf_prog_size(env->insn_cnt), GFP_USER);

			printk("Prog realloc done with return code: %d", err);
			if (!prog) {
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
				return err;
			}
		}

		bpf_ir_free_env(env);
	} else {
		// Filter program, do not run the framework
		return bpf_check(prog_ptr, attr, uattr, uattr_size, NULL);
	}
	return err;
}
