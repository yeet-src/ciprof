ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
VMLINUX := include/vmlinux.h
BPF_SRC := ciprof.bpf.c
BPF_OBJ := bin/ciprof.bpf.o

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)


# Use tp_btf/sched_process_exec for exec tracking — it's more portable than
# fentry/do_execveat_common, which is often compiled as do_execveat_common.isra.0
# and can't be targeted by name. Both deliver exec events; isra loses no useful data.
BPF_CFLAGS += -DUSE_TP_BTF_EXEC

.PHONY: all clean vmlinux

all: $(BPF_OBJ)

$(VMLINUX):
	mkdir -p include
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	mkdir -p bin
	clang $(BPF_CFLAGS) \
		-I include \
		-I /usr/include/$(shell uname -m)-linux-gnu \
		-c $< -o $@

vmlinux: $(VMLINUX)

clean:
	rm -f $(BPF_OBJ)
	rm -f include/vmlinux.h
