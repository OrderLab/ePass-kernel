#ifndef __BPF_IR_KERN_H_
#define __BPF_IR_KERN_H_

#include "linux/bpf.h"

int bpf_ir_kern_run(struct bpf_prog **prog, union bpf_attr *attr,
		    bpfptr_t uattr, u32 uattr_size);

#endif
