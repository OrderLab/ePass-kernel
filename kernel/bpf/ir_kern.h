// SPDX-License-Identifier: GPL-2.0-only
#ifndef __BPF_IR_KERN_H_
#define __BPF_IR_KERN_H_

#include "linux/bpf.h"
#include "linux/bpf_ir.h"
#include "linux/bpf_verifier.h"

int bpf_ir_kern_run(struct bpf_prog **prog_ptr, union bpf_attr *attr,
		    bpfptr_t uattr, u32 uattr_size, const char *pass_opt,
		    const char *global_opt);

// Verifier Information Entry
struct vi_entry {
	bool valid;
	struct bpf_reg_state src_reg_state;
	struct bpf_reg_state dst_reg_state;
	struct bpf_reg_state arg_reg_states[MAX_BPF_FUNC_REG_ARGS];
};

struct vi_entry *get_vi_entry(struct bpf_ir_env *env, u32 insn_idx);

enum bpf_verifier_error {
	BPF_VERIFIER_ERR_0 = 0, // %s has to be at a constant offset
	BPF_VERIFIER_ERR_1 = 1, // cannot pass in %s at an offset=%d
	BPF_VERIFIER_ERR_2 = 2, // cannot pass in %s at an offset=%d
	BPF_VERIFIER_ERR_3 =
		3, // verifier internal error: misconfigured ref_obj_id
	BPF_VERIFIER_ERR_4 = 4, // cannot overwrite referenced dynptr
	BPF_VERIFIER_ERR_5 = 5, // call to invalid destination
	BPF_VERIFIER_ERR_6 = 6, // too many subprograms
	BPF_VERIFIER_ERR_7 = 7, // too many different module BTFs
	BPF_VERIFIER_ERR_8 = 8, // kfunc offset > 0 without fd_array is invalid
	BPF_VERIFIER_ERR_9 = 9, // invalid module BTF fd specified
	BPF_VERIFIER_ERR_10 =
		10, // negative offset disallowed for kernel module function call
	BPF_VERIFIER_ERR_11 =
		11, // calling kernel function is not supported without CONFIG_DEBUG_INFO_BTF
	BPF_VERIFIER_ERR_12 = 12, // JIT is required for calling kernel function
	BPF_VERIFIER_ERR_13 =
		13, // JIT does not support calling kernel function
	BPF_VERIFIER_ERR_14 =
		14, // cannot call kernel function from non-GPL compatible program
	BPF_VERIFIER_ERR_15 = 15, // failed to find BTF for kernel function
	BPF_VERIFIER_ERR_16 = 16, // too many different kernel function calls
	BPF_VERIFIER_ERR_17 = 17, // kernel btf_id %u is not a function
	BPF_VERIFIER_ERR_18 =
		18, // kernel function btf_id %u does not have a valid func_proto
	BPF_VERIFIER_ERR_19 = 19, // cannot find address for kernel function %s
	BPF_VERIFIER_ERR_20 =
		20, // address of kernel function %s is out of range
	BPF_VERIFIER_ERR_21 =
		21, // loading/calling other bpf or kernel functions are allowed for CAP_BPF and CAP_SYS_ADMIN
	BPF_VERIFIER_ERR_22 = 22, // func#%d @%d
	BPF_VERIFIER_ERR_23 = 23, // jump out of range from insn %d to %d
	BPF_VERIFIER_ERR_24 = 24, // last insn is not an exit or jmp
	BPF_VERIFIER_ERR_25 = 25, // verifier BUG type %s var_off %lld off %d
	BPF_VERIFIER_ERR_26 = 26, // R%d is invalid
	BPF_VERIFIER_ERR_27 = 27, // R%d !read_ok
	BPF_VERIFIER_ERR_28 = 28, // frame pointer is read only
	BPF_VERIFIER_ERR_29 = 29, // attempt to corrupt spilled pointer on stack
	BPF_VERIFIER_ERR_30 = 30, // invalid size of register spill
	BPF_VERIFIER_ERR_31 =
		31, // cannot spill pointers to stack into stack frame of the caller
	BPF_VERIFIER_ERR_32 =
		32, // spilled ptr in range of var-offset stack write; insn %d, ptr off: %d
	BPF_VERIFIER_ERR_33 =
		33, // uninit stack in range of var-offset write prohibited for !root; insn %d, off: %d
	BPF_VERIFIER_ERR_34 = 34, // invalid size of register fill
	BPF_VERIFIER_ERR_35 = 35, // invalid read from stack off %d+%d size %d
	BPF_VERIFIER_ERR_36 = 36, // leaking pointer from stack off %d
	BPF_VERIFIER_ERR_37 = 37, // invalid read from stack off %d+%d size %d
	BPF_VERIFIER_ERR_38 =
		38, // variable offset stack pointer cannot be passed into helper function; var_off=%s off=%d size=%d
	BPF_VERIFIER_ERR_39 =
		39, // write into map forbidden, value_size=%d off=%d size=%d
	BPF_VERIFIER_ERR_40 =
		40, // read from map forbidden, value_size=%d off=%d size=%d
	BPF_VERIFIER_ERR_41 =
		41, // R%d min value is negative, either use unsigned index or do a if (index >=0) check.
	BPF_VERIFIER_ERR_42 =
		42, // R%d min value is outside of the allowed memory range
	BPF_VERIFIER_ERR_43 =
		43, // R%d unbounded memory access, make sure to bounds check any such access
	BPF_VERIFIER_ERR_44 =
		44, // R%d max value is outside of the allowed memory range
	BPF_VERIFIER_ERR_45 =
		45, // negative offset %s ptr R%d off=%d disallowed
	BPF_VERIFIER_ERR_46 =
		46, // dereference of modified %s ptr R%d off=%d disallowed
	BPF_VERIFIER_ERR_47 = 47, // variable %s access var_off=%s disallowed
	BPF_VERIFIER_ERR_48 = 48, //
	BPF_VERIFIER_ERR_49 =
		49, // kptr in map can only be accessed using BPF_MEM instruction mode
	BPF_VERIFIER_ERR_50 = 50, // store to referenced kptr disallowed
	BPF_VERIFIER_ERR_51 =
		51, // BPF_ST imm must be 0 when storing to kptr at off=%u
	BPF_VERIFIER_ERR_52 =
		52, // kptr in map can only be accessed using BPF_LDX/BPF_STX/BPF_ST
	BPF_VERIFIER_ERR_53 =
		53, // kptr cannot be accessed indirectly by helper
	BPF_VERIFIER_ERR_54 = 54, // kptr access cannot have variable offset
	BPF_VERIFIER_ERR_55 = 55, // kptr access misaligned expected=%u off=%llu
	BPF_VERIFIER_ERR_56 = 56, // kptr access size must be BPF_DW
	BPF_VERIFIER_ERR_57 =
		57, // %s cannot be accessed directly by load/store
	BPF_VERIFIER_ERR_58 =
		58, // R%d min value is negative, either use unsigned index or do a if (index >=0) check.
	BPF_VERIFIER_ERR_59 = 59, // R%d offset is outside of the packet
	BPF_VERIFIER_ERR_60 = 60, // invalid bpf_context access off=%d size=%d
	BPF_VERIFIER_ERR_61 = 61, // invalid access to flow keys off=%d size=%d
	BPF_VERIFIER_ERR_62 =
		62, // R%d min value is negative, either use unsigned index or do a if (index >=0) check.
	BPF_VERIFIER_ERR_63 = 63, // R%d invalid %s access off=%d size=%d
	BPF_VERIFIER_ERR_64 =
		64, // misaligned packet access off %d+%s+%d+%d size %d
	BPF_VERIFIER_ERR_65 = 65, // misaligned %saccess off %s+%d+%d size %d
	BPF_VERIFIER_ERR_66 =
		66, // tail_calls are not allowed when call stack of previous frames is %d bytes. Too large
	BPF_VERIFIER_ERR_67 =
		67, // combined stack size of %d calls is %d. Too large
	BPF_VERIFIER_ERR_68 =
		68, // verifier bug. subprog has tail_call and async cb
	BPF_VERIFIER_ERR_69 = 69, // the call stack of %d frames is too deep !
	BPF_VERIFIER_ERR_70 =
		70, // R%d invalid %s buffer access: off=%d, size=%d
	BPF_VERIFIER_ERR_71 =
		71, // R%d invalid variable buffer offset: off=%d, var_off=%s
	BPF_VERIFIER_ERR_72 =
		72, // 'struct %s' access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN
	BPF_VERIFIER_ERR_73 =
		73, // Cannot access kernel 'struct %s' from non-GPL compatible program
	BPF_VERIFIER_ERR_74 =
		74, // R%d is ptr_%s invalid negative access: off=%d
	BPF_VERIFIER_ERR_75 =
		75, // R%d is ptr_%s invalid variable offset: off=%d, var_off=%s
	BPF_VERIFIER_ERR_76 = 76, // R%d is ptr_%s access user memory: off=%d
	BPF_VERIFIER_ERR_77 = 77, // R%d is ptr_%s access percpu memory: off=%d
	BPF_VERIFIER_ERR_78 =
		78, // verifier internal error: reg->btf must be kernel btf
	BPF_VERIFIER_ERR_79 = 79, // only read is supported
	BPF_VERIFIER_ERR_80 =
		80, // verifier internal error: ref_obj_id for allocated object must be non-zero
	BPF_VERIFIER_ERR_81 =
		81, // map_ptr access not supported without CONFIG_DEBUG_INFO_BTF
	BPF_VERIFIER_ERR_82 =
		82, // map_ptr access not supported for map type %d
	BPF_VERIFIER_ERR_83 =
		83, // 'struct %s' access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN
	BPF_VERIFIER_ERR_84 = 84, // R%d is %s invalid negative access: off=%d
	BPF_VERIFIER_ERR_85 = 85, // only read from %s is supported
	BPF_VERIFIER_ERR_86 =
		86, // invalid unbounded variable-offset%s stack R%d
	BPF_VERIFIER_ERR_87 = 87, // write to change key R%d not allowed
	BPF_VERIFIER_ERR_88 = 88, // R%d leaks addr into map
	BPF_VERIFIER_ERR_89 = 89, // R%d invalid mem access '%s'
	BPF_VERIFIER_ERR_90 = 90, // R%d cannot write into %s
	BPF_VERIFIER_ERR_91 = 91, // R%d leaks addr into mem
	BPF_VERIFIER_ERR_92 = 92, // R%d leaks addr into ctx
	BPF_VERIFIER_ERR_93 = 93, // cannot write into packet
	BPF_VERIFIER_ERR_94 = 94, // R%d leaks addr into packet
	BPF_VERIFIER_ERR_95 = 95, // R%d leaks addr into flow keys
	BPF_VERIFIER_ERR_96 = 96, // R%d cannot write into %s
	BPF_VERIFIER_ERR_97 = 97, // R%d cannot write into %s
	BPF_VERIFIER_ERR_98 = 98, // R%d invalid mem access '%s'
	BPF_VERIFIER_ERR_99 = 99, // BPF_ATOMIC uses invalid atomic opcode %02x
	BPF_VERIFIER_ERR_100 = 100, // invalid atomic operand size
	BPF_VERIFIER_ERR_101 = 101, // R%d leaks addr into mem
	BPF_VERIFIER_ERR_102 = 102, // R%d leaks addr into mem
	BPF_VERIFIER_ERR_103 =
		103, // BPF_ATOMIC stores into R%d %s is not allowed
	BPF_VERIFIER_ERR_104 = 104, // invalid zero-sized read
	BPF_VERIFIER_ERR_105 =
		105, // R%d%s variable offset stack access prohibited for !root, var_off=%s
	BPF_VERIFIER_ERR_106 =
		106, // potential write to dynptr at off=%d disallowed
	BPF_VERIFIER_ERR_107 = 107, // verifier bug: allocated_stack too small
	BPF_VERIFIER_ERR_108 = 108, // R%d cannot write into %s
	BPF_VERIFIER_ERR_109 = 109, // R%d cannot write into %s
	BPF_VERIFIER_ERR_110 = 110, // R%d cannot write into %s
	BPF_VERIFIER_ERR_111 = 111, // expected=%s
	BPF_VERIFIER_ERR_112 =
		112, // R%d min value is negative, either use unsigned or 'var &= const'
	BPF_VERIFIER_ERR_113 =
		113, // R%d unbounded memory access, use 'var &= const' or 'if (var < const)'
	BPF_VERIFIER_ERR_114 =
		114, // R%d doesn't have constant offset. bpf_spin_lock has to be at the constant offset
	BPF_VERIFIER_ERR_115 =
		115, // map '%s' has to have BTF in order to use bpf_spin_lock
	BPF_VERIFIER_ERR_116 = 116, // %s '%s' has no valid bpf_spin_lock
	BPF_VERIFIER_ERR_117 =
		117, // off %lld doesn't point to 'struct bpf_spin_lock' that is at %d
	BPF_VERIFIER_ERR_118 =
		118, // Locking two bpf_spin_locks are not allowed
	BPF_VERIFIER_ERR_119 = 119, // bpf_spin_unlock without taking a lock
	BPF_VERIFIER_ERR_120 = 120, // bpf_spin_unlock of different lock
	BPF_VERIFIER_ERR_121 =
		121, // R%d doesn't have constant offset. bpf_timer has to be at the constant offset
	BPF_VERIFIER_ERR_122 =
		122, // map '%s' has to have BTF in order to use bpf_timer
	BPF_VERIFIER_ERR_123 = 123, // map '%s' has no valid bpf_timer
	BPF_VERIFIER_ERR_124 =
		124, // off %lld doesn't point to 'struct bpf_timer' that is at %d
	BPF_VERIFIER_ERR_125 =
		125, // verifier bug. Two map pointers in a timer helper
	BPF_VERIFIER_ERR_126 =
		126, // R%d doesn't have constant offset. kptr has to be at the constant offset
	BPF_VERIFIER_ERR_127 =
		127, // map '%s' has to have BTF in order to use bpf_kptr_xchg
	BPF_VERIFIER_ERR_128 = 128, // map '%s' has no valid kptr
	BPF_VERIFIER_ERR_129 = 129, // off=%d doesn't point to kptr
	BPF_VERIFIER_ERR_130 = 130, // off=%d kptr isn't referenced kptr
	BPF_VERIFIER_ERR_131 =
		131, // verifier internal error: misconfigured dynptr helper type flags
	BPF_VERIFIER_ERR_132 = 132, // Dynptr has to be an uninitialized dynptr
	BPF_VERIFIER_ERR_133 =
		133, // cannot pass pointer to const bpf_dynptr, the helper mutates it
	BPF_VERIFIER_ERR_134 = 134, // Expected an initialized dynptr as arg #%d
	BPF_VERIFIER_ERR_135 = 135, // Expected a dynptr of type %s as arg #%d
	BPF_VERIFIER_ERR_136 = 136, // expected uninitialized iter_%s as arg #%d
	BPF_VERIFIER_ERR_137 =
		137, // expected an initialized iter_%s as arg #%d
	BPF_VERIFIER_ERR_138 =
		138, // verifier internal error: unexpected iterator state %d (%s)
	BPF_VERIFIER_ERR_139 = 139, // bug: bad parent state for iter next call
	BPF_VERIFIER_ERR_140 = 140, // invalid map_ptr to access map->type
	BPF_VERIFIER_ERR_141 = 141, // invalid arg_type for sockmap/sockhash
	BPF_VERIFIER_ERR_142 =
		142, // verifier internal error: unsupported arg type %d
	BPF_VERIFIER_ERR_143 = 143, // %s
	BPF_VERIFIER_ERR_144 =
		144, // %s() may write into memory pointed by R%d type=%s
	BPF_VERIFIER_ERR_145 =
		145, // Possibly NULL pointer passed to helper arg%d
	BPF_VERIFIER_ERR_146 =
		146, // verifier internal error: missing arg compatible BTF ID
	BPF_VERIFIER_ERR_147 =
		147, // R%d has non-overwritten BPF_PTR_POISON type
	BPF_VERIFIER_ERR_148 = 148, // R%d is of type %s but %s is expected
	BPF_VERIFIER_ERR_149 =
		149, // verifier internal error: unimplemented handling of MEM_ALLOC
	BPF_VERIFIER_ERR_150 =
		150, // verifier internal error: invalid PTR_TO_BTF_ID register for type match
	BPF_VERIFIER_ERR_151 =
		151, // R%d must have zero offset when passed to release func or trusted arg to kfunc
	BPF_VERIFIER_ERR_152 =
		152, // verifier internal error: multiple dynptr args
	BPF_VERIFIER_ERR_153 =
		153, // verifier internal error: no dynptr arg found
	BPF_VERIFIER_ERR_154 =
		154, // verifier internal error: invalid spi when querying dynptr type
	BPF_VERIFIER_ERR_155 = 155, // R%d leaks addr into helper function
	BPF_VERIFIER_ERR_156 =
		156, // helper access to the packet is not allowed
	BPF_VERIFIER_ERR_157 = 157, // arg %d is an unacquired reference
	BPF_VERIFIER_ERR_158 = 158, // cannot release unowned const bpf_dynptr
	BPF_VERIFIER_ERR_159 =
		159, // R%d must be referenced when passed to release function
	BPF_VERIFIER_ERR_160 =
		160, // verifier internal error: more than one release argument
	BPF_VERIFIER_ERR_161 =
		161, // verifier internal error: more than one arg with ref_obj_id R%d %u %u
	BPF_VERIFIER_ERR_162 =
		162, // timer pointer in R1 map_uid=%d doesn't match map pointer in R2 map_uid=%d
	BPF_VERIFIER_ERR_163 = 163, // invalid map_ptr to access map->key
	BPF_VERIFIER_ERR_164 = 164, // invalid map_ptr to access map->value
	BPF_VERIFIER_ERR_165 = 165, // Helper has invalid btf_id in R%d
	BPF_VERIFIER_ERR_166 = 166, // can't spin_{lock,unlock} in rbtree cb
	BPF_VERIFIER_ERR_167 = 167, // verifier internal error
	BPF_VERIFIER_ERR_168 = 168, // R%d is not a known constant'
	BPF_VERIFIER_ERR_169 = 169, // R%d does not point to a readonly map'
	BPF_VERIFIER_ERR_170 = 170, // R%d is not a constant address'
	BPF_VERIFIER_ERR_171 =
		171, // no direct value access support for this map type
	BPF_VERIFIER_ERR_172 = 172, // direct value access on string failed
	BPF_VERIFIER_ERR_173 = 173, // string is not zero-terminated
	BPF_VERIFIER_ERR_174 = 174, // cannot update sockmap in this context
	BPF_VERIFIER_ERR_175 =
		175, // tail_calls are not allowed in non-JITed programs with bpf-to-bpf calls
	BPF_VERIFIER_ERR_176 = 176, // cannot pass map_type %d into func %s#%d
	BPF_VERIFIER_ERR_177 = 177, // the call stack of %d frames is too deep
	BPF_VERIFIER_ERR_178 = 178, // verifier bug. Frame %d already allocated
	BPF_VERIFIER_ERR_179 =
		179, // verifier bug: kfunc %s#%d not marked as callback-calling
	BPF_VERIFIER_ERR_180 =
		180, // verifier bug: helper %s#%d not marked as callback-calling
	BPF_VERIFIER_ERR_181 =
		181, // verifier bug. No program starts at insn %d
	BPF_VERIFIER_ERR_182 = 182, // Caller passes invalid args into func#%d
	BPF_VERIFIER_ERR_183 = 183, // tail_call abusing map_ptr
	BPF_VERIFIER_ERR_184 = 184, // callback function not allowed for map
	BPF_VERIFIER_ERR_185 = 185, // cannot return stack pointer to the caller
	BPF_VERIFIER_ERR_186 = 186, // R0 not a scalar value
	BPF_VERIFIER_ERR_187 =
		187, // BUG: in callback at %d, callsite %d !calls_callback
	BPF_VERIFIER_ERR_188 = 188, // kernel subsystem misconfigured verifier
	BPF_VERIFIER_ERR_189 = 189, // write into map forbidden
	BPF_VERIFIER_ERR_190 = 190, // kernel subsystem misconfigured verifier
	BPF_VERIFIER_ERR_191 = 191, // verifier bug
	BPF_VERIFIER_ERR_192 = 192, // Invalid format string
	BPF_VERIFIER_ERR_193 =
		193, // func %s#%d supported only for fentry/fexit/fmod_ret programs
	BPF_VERIFIER_ERR_194 =
		194, // func %s#%d not supported for program type %d
	BPF_VERIFIER_ERR_195 = 195, // invalid func %s#%d
	BPF_VERIFIER_ERR_196 = 196, // unknown func %s#%d
	BPF_VERIFIER_ERR_197 =
		197, // cannot call GPL-restricted function from non-GPL compatible program
	BPF_VERIFIER_ERR_198 = 198, // helper call is not allowed in probe
	BPF_VERIFIER_ERR_199 =
		199, // helper call might sleep in a non-sleepable prog
	BPF_VERIFIER_ERR_200 =
		200, // kernel subsystem misconfigured func %s#%d: r1 != ctx
	BPF_VERIFIER_ERR_201 = 201, // kernel subsystem misconfigured func %s#%d
	BPF_VERIFIER_ERR_202 =
		202, // sleepable helper %s#%d in rcu_read_lock region
	BPF_VERIFIER_ERR_203 =
		203, // verifier internal error: CONST_PTR_TO_DYNPTR cannot be released
	BPF_VERIFIER_ERR_204 =
		204, // func %s#%d reference has not been acquired before
	BPF_VERIFIER_ERR_205 = 205, // tail_call would lead to reference leak
	BPF_VERIFIER_ERR_206 =
		206, // get_local_storage() doesn't support non-zero flags
	BPF_VERIFIER_ERR_207 =
		207, // Unsupported reg type %s for bpf_dynptr_from_mem data
	BPF_VERIFIER_ERR_208 =
		208, // BPF_LSM_CGROUP that attach to void LSM hooks can't modify return value!
	BPF_VERIFIER_ERR_209 =
		209, // verifier internal error: meta.dynptr_id already set
	BPF_VERIFIER_ERR_210 =
		210, // verifier internal error: meta.ref_obj_id already set
	BPF_VERIFIER_ERR_211 =
		211, // verifier internal error: failed to obtain dynptr id
	BPF_VERIFIER_ERR_212 =
		212, // verifier internal error: failed to obtain dynptr ref_obj_id
	BPF_VERIFIER_ERR_213 = 213, // kernel subsystem misconfigured verifier
	BPF_VERIFIER_ERR_214 =
		214, // unable to resolve the size of type '%s': %ld
	BPF_VERIFIER_ERR_215 =
		215, // func %s has non-overwritten BPF_PTR_POISON return type
	BPF_VERIFIER_ERR_216 = 216, // invalid return type %u of func %s#%d
	BPF_VERIFIER_ERR_217 = 217, // unknown return type %u of func %s#%d
	BPF_VERIFIER_ERR_218 =
		218, // verifier internal error: func %s#%d sets ref_obj_id more than once
	BPF_VERIFIER_ERR_219 = 219, // max struct nesting depth exceeded
	BPF_VERIFIER_ERR_220 =
		220, // kernel function %s args#%d pointer type %s %s is not supported
	BPF_VERIFIER_ERR_221 =
		221, // arg#%d pointer type %s %s must point to %sscalar, or struct with scalar
	BPF_VERIFIER_ERR_222 =
		222, // kernel function %s args#%d expected pointer to %s %s but R%d has a pointer to %s %s
	BPF_VERIFIER_ERR_223 =
		223, // verifier internal error: ref_set_non_owning w/o active lock
	BPF_VERIFIER_ERR_224 =
		224, // verifier internal error: NON_OWN_REF already set
	BPF_VERIFIER_ERR_225 =
		225, // verifier internal error: ref_obj_id is zero for
	BPF_VERIFIER_ERR_226 =
		226, // verifier internal error: ref state missing for ref_obj_id
	BPF_VERIFIER_ERR_227 =
		227, // verifier internal error: unknown reg type for lock check
	BPF_VERIFIER_ERR_228 =
		228, // held lock and object are not in the same allocation
	BPF_VERIFIER_ERR_229 =
		229, // verifier internal error: unexpected graph root argument type %s
	BPF_VERIFIER_ERR_230 =
		230, // verifier internal error: %s head arg for unknown kfunc
	BPF_VERIFIER_ERR_231 =
		231, // verifier internal error: unexpected graph node argument type %s
	BPF_VERIFIER_ERR_232 =
		232, // verifier internal error: %s node arg for unknown kfunc
	BPF_VERIFIER_ERR_233 =
		233, // verifier internal error: unexpected btf mismatch in kfunc call
	BPF_VERIFIER_ERR_234 =
		234, // R%d doesn't have constant offset. %s has to be at the constant offset
	BPF_VERIFIER_ERR_235 = 235, // %s not found at offset=%u
	BPF_VERIFIER_ERR_236 =
		236, // bpf_spin_lock at off=%d must be held for %s
	BPF_VERIFIER_ERR_237 = 237, // verifier internal error: repeating %s arg
	BPF_VERIFIER_ERR_238 =
		238, // verifier internal error: unexpected btf mismatch in kfunc call
	BPF_VERIFIER_ERR_239 =
		239, // R%d doesn't have constant offset. %s has to be at the constant offset
	BPF_VERIFIER_ERR_240 = 240, // %s not found at offset=%u
	BPF_VERIFIER_ERR_241 =
		241, // operation on %s expects arg#1 %s at offset=%d
	BPF_VERIFIER_ERR_242 =
		242, // arg#1 offset=%d, but expected %s at offset=%d in struct %s
	BPF_VERIFIER_ERR_243 = 243, // Function %s has %d > %d args
	BPF_VERIFIER_ERR_244 = 244, // R%d is not a scalar
	BPF_VERIFIER_ERR_245 =
		245, // verifier internal error: only one constant argument permitted
	BPF_VERIFIER_ERR_246 = 246, // R%d must be a known constant
	BPF_VERIFIER_ERR_247 =
		247, // 2 or more rdonly/rdwr_buf_size parameters for kfunc
	BPF_VERIFIER_ERR_248 = 248, // R%d is not a const
	BPF_VERIFIER_ERR_249 = 249, // Unrecognized arg#%d type %s
	BPF_VERIFIER_ERR_250 =
		250, // Possibly NULL pointer passed to trusted arg%d
	BPF_VERIFIER_ERR_251 =
		251, // verifier internal error: more than one arg with ref_obj_id R%d %u %u
	BPF_VERIFIER_ERR_252 = 252, // R%d must be referenced or trusted
	BPF_VERIFIER_ERR_253 = 253, // R%d must be a rcu pointer
	BPF_VERIFIER_ERR_254 =
		254, // arg#%d expected pointer to ctx, but got %s
	BPF_VERIFIER_ERR_255 =
		255, // arg#%d expected pointer to allocated object
	BPF_VERIFIER_ERR_256 = 256, // allocated object must be referenced
	BPF_VERIFIER_ERR_257 =
		257, // arg#%d expected pointer to stack or dynptr_ptr
	BPF_VERIFIER_ERR_258 =
		258, // verifier internal error: no dynptr type for parent of clone
	BPF_VERIFIER_ERR_259 =
		259, // verifier internal error: missing ref obj id for parent of clone
	BPF_VERIFIER_ERR_260 =
		260, // verifier internal error: failed to obtain dynptr id
	BPF_VERIFIER_ERR_261 =
		261, // arg#%d expected pointer to map value or allocated object
	BPF_VERIFIER_ERR_262 = 262, // allocated object must be referenced
	BPF_VERIFIER_ERR_263 =
		263, // arg#%d expected pointer to map value or allocated object
	BPF_VERIFIER_ERR_264 = 264, // allocated object must be referenced
	BPF_VERIFIER_ERR_265 =
		265, // arg#%d expected pointer to allocated object
	BPF_VERIFIER_ERR_266 = 266, // allocated object must be referenced
	BPF_VERIFIER_ERR_267 =
		267, // rbtree_remove node input must be non-owning ref
	BPF_VERIFIER_ERR_268 = 268, // rbtree_remove not allowed in rbtree cb
	BPF_VERIFIER_ERR_269 =
		269, // arg#%d expected pointer to allocated object
	BPF_VERIFIER_ERR_270 = 270, // allocated object must be referenced
	BPF_VERIFIER_ERR_271 = 271, // expected %s or socket
	BPF_VERIFIER_ERR_272 =
		272, // arg#%d reference type('%s %s') size cannot be determined: %ld
	BPF_VERIFIER_ERR_273 =
		273, // arg#%d arg#%d memory, len pair leads to invalid memory access
	BPF_VERIFIER_ERR_274 =
		274, // verifier internal error: only one constant argument permitted
	BPF_VERIFIER_ERR_275 = 275, // R%d must be a known constant
	BPF_VERIFIER_ERR_276 = 276, // arg%d expected pointer to func
	BPF_VERIFIER_ERR_277 =
		277, // arg#%d is neither owning or non-owning ref
	BPF_VERIFIER_ERR_278 =
		278, // verifier internal error: Couldn't find btf_record
	BPF_VERIFIER_ERR_279 =
		279, // arg#%d doesn't point to a type with bpf_refcount field
	BPF_VERIFIER_ERR_280 =
		280, // release kernel function %s expects refcounted PTR_TO_BTF_ID
	BPF_VERIFIER_ERR_281 =
		281, // destructive kfunc calls require CAP_SYS_BOOT capability
	BPF_VERIFIER_ERR_282 =
		282, // program must be sleepable to call sleepable kfunc %s
	BPF_VERIFIER_ERR_283 = 283, // kfunc %s#%d failed callback verification
	BPF_VERIFIER_ERR_284 =
		284, // Calling bpf_rcu_read_{lock,unlock} in unnecessary rbtree callback
	BPF_VERIFIER_ERR_285 = 285, // nested rcu read lock (kernel function %s)
	BPF_VERIFIER_ERR_286 =
		286, // kernel func %s is sleepable within rcu_read_lock region
	BPF_VERIFIER_ERR_287 =
		287, // unmatched rcu read unlock (kernel function %s)
	BPF_VERIFIER_ERR_288 =
		288, // kfunc %s#%d reference has not been acquired before
	BPF_VERIFIER_ERR_289 =
		289, // kfunc %s#%d conversion of owning ref to non-owning failed
	BPF_VERIFIER_ERR_290 =
		290, // kfunc %s#%d reference has not been acquired before
	BPF_VERIFIER_ERR_291 =
		291, // acquire kernel function does not return PTR_TO_BTF_ID
	BPF_VERIFIER_ERR_292 =
		292, // local type ID argument must be in range [0, U32_MAX]
	BPF_VERIFIER_ERR_293 = 293, // bpf_obj_new requires prog BTF
	BPF_VERIFIER_ERR_294 =
		294, // bpf_obj_new type ID argument must be of a struct
	BPF_VERIFIER_ERR_295 =
		295, // kfunc bpf_rdonly_cast type ID argument must be of a struct
	BPF_VERIFIER_ERR_296 =
		296, // verifier internal error: bpf_dynptr_slice(_rdwr) no constant size
	BPF_VERIFIER_ERR_297 =
		297, // the prog does not allow writes to packet data
	BPF_VERIFIER_ERR_298 = 298, // verifier internal error: no dynptr id
	BPF_VERIFIER_ERR_299 =
		299, // kernel function %s unhandled dynamic return type
	BPF_VERIFIER_ERR_300 =
		300, // kernel function %s returns pointer type %s %s is not supported
	BPF_VERIFIER_ERR_301 =
		301, // math between %s pointer and %lld is not allowed
	BPF_VERIFIER_ERR_302 = 302, // %s pointer offset %d is not allowed
	BPF_VERIFIER_ERR_303 =
		303, // math between %s pointer and register with unbounded min value is not allowed
	BPF_VERIFIER_ERR_304 =
		304, // value %lld makes %s pointer be out of bounds
	BPF_VERIFIER_ERR_305 =
		305, // R%d variable stack access prohibited for !root, var_off=%s off=%d
	BPF_VERIFIER_ERR_306 =
		306, // R%d pointer arithmetic of map value goes out of range,
	BPF_VERIFIER_ERR_307 = 307, // R%d 32-bit pointer arithmetic prohibited
	BPF_VERIFIER_ERR_308 =
		308, // R%d pointer arithmetic on %s prohibited, null-check it first
	BPF_VERIFIER_ERR_309 = 309, // R%d pointer arithmetic on %s prohibited
	BPF_VERIFIER_ERR_310 = 310, // R%d tried to subtract pointer from scalar
	BPF_VERIFIER_ERR_311 =
		311, // R%d subtraction from stack pointer prohibited
	BPF_VERIFIER_ERR_312 =
		312, // R%d bitwise operator %s on pointer prohibited
	BPF_VERIFIER_ERR_313 =
		313, // R%d pointer arithmetic with %s operator prohibited
	BPF_VERIFIER_ERR_314 = 314, // R%d pointer %s pointer prohibited
	BPF_VERIFIER_ERR_315 =
		315, // verifier internal error: unexpected ptr_reg
	BPF_VERIFIER_ERR_316 = 316, // verifier internal error: no src_reg
	BPF_VERIFIER_ERR_317 = 317, // BPF_NEG uses reserved fields
	BPF_VERIFIER_ERR_318 = 318, // BPF_END uses reserved fields
	BPF_VERIFIER_ERR_319 = 319, // R%d pointer arithmetic prohibited
	BPF_VERIFIER_ERR_320 = 320, // BPF_MOV uses reserved fields
	BPF_VERIFIER_ERR_321 = 321, // BPF_MOV uses reserved fields
	BPF_VERIFIER_ERR_322 = 322, // BPF_MOV uses reserved fields
	BPF_VERIFIER_ERR_323 = 323, // BPF_MOV uses reserved fields
	BPF_VERIFIER_ERR_324 = 324, // R%d sign-extension part of pointer
	BPF_VERIFIER_ERR_325 = 325, // R%d partial copy of pointer
	BPF_VERIFIER_ERR_326 = 326, // invalid BPF_ALU opcode %x
	BPF_VERIFIER_ERR_327 = 327, // BPF_ALU uses reserved fields
	BPF_VERIFIER_ERR_328 = 328, // BPF_ALU uses reserved fields
	BPF_VERIFIER_ERR_329 = 329, // div by zero
	BPF_VERIFIER_ERR_330 = 330, // invalid shift %d
	BPF_VERIFIER_ERR_331 = 331, // invalid BPF_JMP/JMP32 opcode %x
	BPF_VERIFIER_ERR_332 = 332, // BPF_JMP/JMP32 uses reserved fields
	BPF_VERIFIER_ERR_333 = 333, // R%d pointer comparison prohibited
	BPF_VERIFIER_ERR_334 = 334, // BPF_JMP/JMP32 uses reserved fields
	BPF_VERIFIER_ERR_335 = 335, // R%d pointer comparison prohibited
	BPF_VERIFIER_ERR_336 = 336, // invalid BPF_LD_IMM insn
	BPF_VERIFIER_ERR_337 = 337, // BPF_LD_IMM64 uses reserved fields
	BPF_VERIFIER_ERR_338 = 338, // bpf verifier is misconfigured
	BPF_VERIFIER_ERR_339 = 339, // missing btf func_info
	BPF_VERIFIER_ERR_340 = 340, // callback function not static
	BPF_VERIFIER_ERR_341 = 341, // bpf verifier is misconfigured
	BPF_VERIFIER_ERR_342 =
		342, // BPF_LD_[ABS|IND] instructions not allowed for this program type
	BPF_VERIFIER_ERR_343 = 343, // bpf verifier is misconfigured
	BPF_VERIFIER_ERR_344 = 344, // BPF_LD_[ABS|IND] uses reserved fields
	BPF_VERIFIER_ERR_345 =
		345, // BPF_LD_[ABS|IND] cannot be mixed with socket references
	BPF_VERIFIER_ERR_346 =
		346, // BPF_LD_[ABS|IND] cannot be used inside bpf_spin_lock-ed region
	BPF_VERIFIER_ERR_347 =
		347, // BPF_LD_[ABS|IND] cannot be used inside bpf_rcu_read_lock-ed region
	BPF_VERIFIER_ERR_348 =
		348, // at the time of BPF_LD_ABS|IND R6 != pointer to skb
	BPF_VERIFIER_ERR_349 = 349, // R0 leaks addr as return value
	BPF_VERIFIER_ERR_350 =
		350, // In async callback the register R0 is not a known value (%s)
	BPF_VERIFIER_ERR_351 =
		351, // At subprogram exit the register R0 is not a scalar value (%s)
	BPF_VERIFIER_ERR_352 =
		352, // At program exit the register R0 is not a known value (%s)
	BPF_VERIFIER_ERR_353 =
		353, // Note, BPF_LSM_CGROUP that attach to void LSM hooks can't modify return value!
	BPF_VERIFIER_ERR_354 = 354, // jump out of range from insn %d to %d
	BPF_VERIFIER_ERR_355 = 355, // back-edge from insn %d to %d
	BPF_VERIFIER_ERR_356 = 356, // insn state internal bug
	BPF_VERIFIER_ERR_357 =
		357, // LD_ABS is not allowed in subprogs without BTF
	BPF_VERIFIER_ERR_358 =
		358, // tail_call is not allowed in subprogs without BTF
	BPF_VERIFIER_ERR_359 =
		359, // number of funcs in func_info doesn't match number of subprogs
	BPF_VERIFIER_ERR_360 = 360, // invalid func info rec size %u
	BPF_VERIFIER_ERR_361 =
		361, // same insn cannot be used with different pointers
	BPF_VERIFIER_ERR_362 = 362, // invalid insn idx %d insn_cnt %d
	BPF_VERIFIER_ERR_363 =
		363, // BPF program is too large. Processed %d insn
	BPF_VERIFIER_ERR_364 = 364, // BPF_STX uses reserved fields
	BPF_VERIFIER_ERR_365 = 365, // BPF_ST uses reserved fields
	BPF_VERIFIER_ERR_366 = 366, // BPF_CALL uses reserved fields
	BPF_VERIFIER_ERR_367 =
		367, // function calls are not allowed while holding a lock
	BPF_VERIFIER_ERR_368 = 368, // BPF_JA uses reserved fields
	BPF_VERIFIER_ERR_369 = 369, // BPF_EXIT uses reserved fields
	BPF_VERIFIER_ERR_370 = 370, // bpf_spin_unlock is missing
	BPF_VERIFIER_ERR_371 = 371, // bpf_rcu_read_unlock is missing
	BPF_VERIFIER_ERR_372 = 372, // invalid BPF_LD mode
	BPF_VERIFIER_ERR_373 = 373, // unknown insn class %d
	BPF_VERIFIER_ERR_374 = 374, // invalid module BTF object FD specified.
	BPF_VERIFIER_ERR_375 =
		375, // kernel is missing BTF, make sure CONFIG_DEBUG_INFO_BTF=y is specified in Kconfig.
	BPF_VERIFIER_ERR_376 =
		376, // tracing progs cannot use bpf_{list_head,rb_root} yet
	BPF_VERIFIER_ERR_377 =
		377, // socket filter progs cannot use bpf_spin_lock yet
	BPF_VERIFIER_ERR_378 =
		378, // tracing progs cannot use bpf_spin_lock yet
	BPF_VERIFIER_ERR_379 = 379, // tracing progs cannot use bpf_timer yet
	BPF_VERIFIER_ERR_380 =
		380, // offload device mismatch between prog and map
	BPF_VERIFIER_ERR_381 = 381, // bpf_struct_ops map cannot be used in prog
	BPF_VERIFIER_ERR_382 =
		382, // Sleepable programs can only use array, hash, ringbuf and local storage maps
	BPF_VERIFIER_ERR_383 = 383, // BPF_LDX uses reserved fields
	BPF_VERIFIER_ERR_384 = 384, // invalid bpf_ld_imm64 insn
	BPF_VERIFIER_ERR_385 = 385, // unrecognized bpf_ld_imm64 insn
	BPF_VERIFIER_ERR_386 = 386, // fd_idx without fd_array is invalid
	BPF_VERIFIER_ERR_387 = 387, // fd %d is not pointing to valid bpf_map
	BPF_VERIFIER_ERR_388 = 388, // unknown opcode %02x
	BPF_VERIFIER_ERR_389 =
		389, // verifier bug. zext_dst is set, but no reg is defined
	BPF_VERIFIER_ERR_390 = 390, // bpf verifier is misconfigured
	BPF_VERIFIER_ERR_391 = 391, // bpf verifier is misconfigured
	BPF_VERIFIER_ERR_392 =
		392, // bpf verifier narrow ctx access misconfigured
	BPF_VERIFIER_ERR_393 = 393, // bpf verifier is misconfigured
	BPF_VERIFIER_ERR_394 =
		394, // bpf verifier narrow ctx load misconfigured
	BPF_VERIFIER_ERR_395 =
		395, // calling kernel functions are not allowed in non-JITed programs
	BPF_VERIFIER_ERR_396 =
		396, // tail_calls are not allowed in non-JITed programs with bpf-to-bpf calls
	BPF_VERIFIER_ERR_397 =
		397, // callbacks are not allowed in non-JITed programs
	BPF_VERIFIER_ERR_398 =
		398, // invalid kernel function call not eliminated in verifier pass
	BPF_VERIFIER_ERR_399 =
		399, // verifier internal error: kernel function descriptor not found for func_id %u
	BPF_VERIFIER_ERR_400 =
		400, // verifier internal error: kptr_struct_meta expected at insn_idx %d
	BPF_VERIFIER_ERR_401 =
		401, // verifier internal error: kptr_struct_meta expected at insn_idx %d
	BPF_VERIFIER_ERR_402 = 402, // bpf verifier is misconfigured
	BPF_VERIFIER_ERR_403 = 403, // adding tail call poke descriptor failed
	BPF_VERIFIER_ERR_404 = 404, // tail_call abusing map_ptr
	BPF_VERIFIER_ERR_405 = 405, // bpf verifier is misconfigured
	BPF_VERIFIER_ERR_406 = 406, // kernel subsystem misconfigured func %s#%d
	BPF_VERIFIER_ERR_407 = 407, // bpf verifier is misconfigured
	BPF_VERIFIER_ERR_408 = 408, // tracking tail call prog failed
	BPF_VERIFIER_ERR_409 =
		409, // struct ops programs must have a GPL compatible license
	BPF_VERIFIER_ERR_410 =
		410, // attach_btf_id %u is not a supported struct
	BPF_VERIFIER_ERR_411 =
		411, // attach to invalid member idx %u of struct %s
	BPF_VERIFIER_ERR_412 =
		412, // attach to invalid member %s(@idx %u) of struct %s
	BPF_VERIFIER_ERR_413 =
		413, // attach to unsupported member %s of struct %s
	BPF_VERIFIER_ERR_414 = 414, // Syscall programs can only be sleepable
	BPF_VERIFIER_ERR_415 =
		415, // Only fentry/fexit/fmod_ret, lsm, iter, uprobe, and struct_ops programs can be sleepable

};

bool bpf_ir_canfix(struct bpf_ir_env *env);

// Kernel passes

extern const struct custom_pass_cfg bpf_ir_kern_masking_pass;

extern const struct builtin_pass_cfg bpf_ir_kern_pointer_check;

#endif
