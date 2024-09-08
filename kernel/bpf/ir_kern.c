// bpf_ir kernel functions

#include "ir_kern.h"
#include "linux/bpf_ir.h"

int bpf_ir_kern_run(struct bpf_prog *prog, enum bpf_prog_type type)
{
    int err = 0;
	if (type != BPF_PROG_TYPE_SOCKET_FILTER) {
		struct bpf_ir_env *bpf_ir_env = bpf_ir_init_env();
		if (!bpf_ir_env) {
			return -ENOMEM;
		}
		err = bpf_ir_run(bpf_ir_env, prog->insnsi, prog->len);
		if (err < 0)
			return err;
		bpf_ir_print_log_dbg(bpf_ir_env);
		bpf_ir_free_env(bpf_ir_env);
	}
	return 0;
}