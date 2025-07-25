#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[256];
	char command[256];
	int ret = 0;
	FILE *f;

	if (!argv[1]) {
		fprintf(stderr, "ERROR: Run with the btrfs device argument!\n");
		return 0;
	}

	snprintf(filename, sizeof(filename), "%s.bpf.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	prog = bpf_object__find_program_by_name(obj, "bpf_prog1");
	if (!prog) {
		fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
		goto cleanup;
	}

	/* load BPF program */
	if (bpf_object__load(obj, 0, NULL, NULL)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}

	snprintf(command, 256, "mount %s tmpmnt/", argv[1]);
	f = popen(command, "r");
	ret = pclose(f);

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return ret ? 0 : 1;
}
