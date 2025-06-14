# Makefile for eBPF case insensitivity detector

# --- Configuration ---
# Kernel headers for bpf_helpers.h, etc.
# Adjust KERNEL_HEADERS if your kernel headers are in a non-standard location
KERNEL_HEADERS ?= /usr/src/linux-headers-$(shell uname -r)/include


# Clang and LLVM for BPF compilation
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool


# libbpf source directory (for includes and potentially static linking)
# If libbpf is installed system-wide, you might not need this.
# Example: LIBBPF_SRC ?= $(HOME)/src/libbpf
# LIBBPF_SRC ?= /usr/src/libbpf # Common path if installed from kernel source


# --- Directories and Files ---
# Source files relative to this Makefile (which is in src/)
BPF_SRC = bpf/detector.bpf.c
USER_SRC = user/detector_user.c


# Build output directories
# IMPORTANT: BUILD_DIR is relative to this Makefile (src/)
# So ../build means one level up from src/
BUILD_DIR := ../build
BPF_OUT_DIR := $(BUILD_DIR)/bpf
BPF_INTERNAL_INCLUDE_DIR := $(BPF_OUT_DIR)/internal# New directory for vmlinux.h


# Output files
BPF_OBJ := $(BPF_OUT_DIR)/detector.bpf.o
BPF_SKELETON := $(BPF_OUT_DIR)/detector.bpf.h
USER_BIN := $(BUILD_DIR)/detector
VMLINUX_H := $(BPF_INTERNAL_INCLUDE_DIR)/vmlinux.h# Updated path


# List of all directories to create
REQUIRED_DIRS := $(BPF_OUT_DIR) $(BPF_INTERNAL_INCLUDE_DIR) # Added new directory


# --- Compiler Flags ---
# BPF compiler flags
# Determine architecture for __TARGET_ARCH_xxx
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/riscv64/riscv/')
# Base directory for kernel source/headers, e.g., /usr/src/linux-headers-5.15.0-116-generic
KERNEL_BASE_DIR := $(patsubst %/include,%,$(KERNEL_HEADERS))
KERNEL_ARCH_INCLUDE_DIR := $(KERNEL_BASE_DIR)/arch/$(ARCH)/include
KERNEL_ARCH_UAPI_INCLUDE_DIR := $(KERNEL_ARCH_INCLUDE_DIR)/uapi
KERNEL_ARCH_GENERATED_INCLUDE_DIR := $(KERNEL_ARCH_INCLUDE_DIR)/generated
KERNEL_ARCH_GENERATED_UAPI_INCLUDE_DIR := $(KERNEL_ARCH_GENERATED_INCLUDE_DIR)/uapi # Usually not needed for types.h but can be added if other generated uapi headers are missing


BPF_CFLAGS = -target bpf -O2 -g -Wall -Werror \
             -D__TARGET_ARCH_$(ARCH) \
             -I$(BPF_INTERNAL_INCLUDE_DIR) \
             -I$(KERNEL_HEADERS) \
             -I$(KERNEL_ARCH_INCLUDE_DIR) \
             -I$(KERNEL_ARCH_UAPI_INCLUDE_DIR) \
             -I$(KERNEL_ARCH_GENERATED_INCLUDE_DIR) \
             -I$(KERNEL_ARCH_GENERATED_UAPI_INCLUDE_DIR) \
             -I/usr/include/bpf # For bpf_helpers.h etc. from libbpf, adjust if needed


# User-space compiler flags
# $(BPF_OUT_DIR) for the generated skeleton header
USER_CFLAGS = -g -Wall -Werror -Wno-unknown-attributes -I$(BPF_OUT_DIR) # For the generated skeleton
USER_LDFLAGS = -lbpf -lz -lelf # Common libraries for libbpf applications


# --- Phony Targets ---
.PHONY: all clean directories


# --- Main Targets ---
all: directories $(USER_BIN)


# Rule to create all necessary directories
directories:
	@echo "Creating directories: $(REQUIRED_DIRS)"
	@mkdir -p $(REQUIRED_DIRS)


# Rule for the user-space binary
# Depends on the user source code and the generated BPF skeleton header
$(USER_BIN): $(USER_SRC) $(BPF_SKELETON)
	@echo "Building user-space program: $@"
	$(CLANG) $(USER_CFLAGS) $(USER_SRC) $(USER_LDFLAGS) -o $@


# Rule to generate BPF skeleton header from the BPF object file
$(BPF_SKELETON): $(BPF_OBJ)
	@echo "Generating BPF skeleton header: $@"
	$(BPFTOOL) gen skeleton $< > $@


# Rule for the BPF object file
# Depends on the BPF source code and vmlinux.h (for CO-RE)
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H)
	@echo "Building BPF object: $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@


# Rule to generate vmlinux.h (needed for kernel struct definitions in BPF code using CO-RE)
# This requires bpftool and access to /sys/kernel/btf/vmlinux
# The prerequisite $(BPF_INTERNAL_INCLUDE_DIR) ensures the directory exists,
# which will be created by the 'directories' target.
$(VMLINUX_H): | $(BPF_INTERNAL_INCLUDE_DIR)
	@echo "Generating vmlinux.h for BPF CO-RE (requires /sys/kernel/btf/vmlinux)..."
	@echo "DEBUG: BUILD_DIR is [$(BUILD_DIR)]"
	@echo "DEBUG: BPF_OUT_DIR is [$(BPF_OUT_DIR)]"
	@echo "DEBUG: BPF_INTERNAL_INCLUDE_DIR is [$(BPF_INTERNAL_INCLUDE_DIR)]"
	@echo "DEBUG: VMLINUX_H variable is [$(VMLINUX_H)]"
	@echo "VMLINUX_H target path ($$@): [$@]"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > "$@"


# --- Cleaning ---
clean:
	@echo "Cleaning up build artifacts..."
	rm -rf $(BUILD_DIR)