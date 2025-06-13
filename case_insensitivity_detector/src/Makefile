# Makefile for eBPF case insensitivity detector


# --- Configuration ---
# Kernel headers for bpf_helpers.h, etc.
# Adjust KERNEL_HEADERS if your kernel headers are in a non-standard location
KERNEL_HEADERS ?= /usr/src/linux-headers-$(shell uname -r)/include


# Clang and LLVM for BPF compilation
CLANG ?= clang
LLVM_STRIP ?= llvm-strip


# libbpf source directory (for includes and potentially static linking)
# If libbpf is installed system-wide, you might not need this.
# Example: LIBBPF_SRC ?= $(HOME)/src/libbpf
LIBBPF_SRC ?= /usr/src/libbpf # Common path if installed from kernel source


# --- Directories and Files ---
BPF_SRC = src/bpf/detector.bpf.c
USER_SRC = src/user/detector_user.c


# Build output directories
BUILD_DIR = build
BPF_OUT_DIR = $(BUILD_DIR)/bpf
USER_OUT_DIR = $(BUILD_DIR)/user


# Output files
BPF_OBJ = $(BPF_OUT_DIR)/detector.bpf.o
USER_BIN = $(BUILD_DIR)/detector # Place executable in build directory
VMLINUX_H = $(BPF_OUT_DIR)/vmlinux.h


# --- Compiler Flags ---
# BPF compiler flags
BPF_CFLAGS = -target bpf -O2 -g -D__KERNEL__ -I$(KERNEL_HEADERS) -I$(LIBBPF_SRC)/include
BPF_LDFLAGS =


# User-space compiler flags
USER_CFLAGS = -g -Wall -I$(BPF_OUT_DIR) # Include generated BPF header dir
USER_LDFLAGS = -lbpf -lz -lelf          # Link against libbpf, zlib, elf


# --- Phony Targets ---
.PHONY: all clean


# --- Main Targets ---
all: $(USER_BIN)


$(USER_BIN): $(BPF_OBJ) $(USER_SRC)
   @mkdir -p $(USER_OUT_DIR)
   @echo "Building user-space program: $@"
   $(CLANG) $(USER_SRC) $(BPF_OBJ) $(USER_CFLAGS) $(USER_LDFLAGS) -o $@


$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H)
   @mkdir -p $(dir $@)
   @echo "Building BPF object: $@"
   $(CLANG) $(BPF_CFLAGS) -c $< -o $@


# Rule to generate vmlinux.h (needed for kernel struct definitions in BPF code)
$(VMLINUX_H):
   @mkdir -p $(dir $@)
   @echo "Generating vmlinux.h for BPF code..."
   bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@


# --- Cleaning ---
clean:
   @echo "Cleaning up build artifacts..."
   rm -rf $(BUILD_DIR) $(USER_BIN) # Remove both build directory and the final executable
