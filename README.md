# Case Insensitivity Detector

This project uses eBPF to monitor file system operations (`vfs_lookup` and `vfs_create`) in the Linux kernel, reporting case mismatches between requested and actual file names. It consists of a BPF program and a user-space application.

## Prerequisites

- **Linux Kernel:** 5.x or newer (for CO-RE support)
- **Kernel Headers:** Install for your running kernel (`linux-headers-$(uname -r)` on Debian/Ubuntu)
- **Compiler Toolchain:**  
  - `clang` and `llvm` (version 10+ recommended)  
  - `make`
- **libbpf:** Install `libbpf-dev` (Debian/Ubuntu) or `libbpf-devel` (Fedora/RHEL)
- **bpftool:** For generating `vmlinux.h` and BPF skeleton (`linux-tools-$(uname -r)` on Debian/Ubuntu)

## Building

1. **Navigate to the `src` directory:**
    ```bash
    cd /Users/mona/Desktop/classes/CS260/project/case_insensitivity_detector/src
    ```

2. **Clean previous builds (optional):**
    ```bash
    make clean
    ```

3. **Build the project:**
    ```bash
    make
    ```
    This compiles the BPF program, generates the skeleton, and builds the user-space binary in `build/detector`.

## Running

1. **Run the user-space application as root:**
    ```bash
    sudo ./build/detector
    ```
    You should see:
    ```
    Successfully loaded and attached BPF programs. Monitoring vfs_lookup and vfs_create...
    Press Ctrl-C to exit.
    ```

2. **Trigger file system events in another terminal:**
    - Lookup:
        ```bash
        ls some_existing_file.txt
        cat another_file.txt
        cd some_directory/
        ```
    - Create:
        ```bash
        touch new_test_file.txt
        mkdir my_new_folder
        ```
    - To test case mismatches (if your filesystem is case-insensitive or case-preserving):
        ```bash
        # If MyFile.TXT exists
        ls myfile.txt
        # Or try to create a file with a different case
        touch file.txt
        ```

3. **Observe output in the detector terminal.**

4. **Stop the program:**  
   Press `Ctrl-C` in the detector terminal.

## Troubleshooting

- Ensure all dependencies are installed.
- If you see BPF verifier errors, check your kernel version and code for compatibility.
- If `make` fails, check for missing headers or libraries.

## Notes

- You must run as root to load BPF programs and attach kprobes.
- The program is designed for educational/research use on supported Linux systems.

---
**Author:**  
Mona Ibrahim