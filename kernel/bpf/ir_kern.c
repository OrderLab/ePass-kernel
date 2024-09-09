// bpf_ir kernel functions

#include "ir_kern.h"
#include "linux/bpf_ir.h"
#include "linux/bpf.h"

static inline unsigned int bpf_prog_size(unsigned int proglen)
{
	return max(sizeof(struct bpf_prog),
		   offsetof(struct bpf_prog, insns[proglen]));
}

int bpf_ir_kern_run(struct bpf_prog **prog_ptr, enum bpf_prog_type type)
{
	int err = 0;
	struct bpf_prog *prog = *prog_ptr;
	if (type != BPF_PROG_TYPE_SOCKET_FILTER) {
		// TODO: Check if the program is offloaded to the hardware
		// If not, do no run the pipeline
		struct bpf_ir_env *env = bpf_ir_init_env();
		if (!env) {
			return -ENOMEM;
		}
		err = bpf_ir_run(env, prog->insnsi, prog->len);
		if (err < 0)
			return err;

		/* Kernel Start */
		prog = bpf_prog_realloc(prog, bpf_prog_size(env->insn_cnt),
					 GFP_USER);
		if (prog) {
			return -ENOMEM;
		}
		*prog_ptr = prog;
		memcpy(prog->insnsi, env->insns, env->insn_cnt * sizeof(struct bpf_insn));
		prog->len = env->insn_cnt;

		/* Kernel End */

		bpf_ir_print_log_dbg(env);
		bpf_ir_free_env(env);
	}
	return 0;
}
