#include "vmlinux.h" // For kernel types
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef IS_ERR
// From <linux/err.h>
#define MAX_ERRNO       4095
#define IS_ERR_VALUE(x) ((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)
#define IS_ERR(ptr)     IS_ERR_VALUE((unsigned long)(ptr))
#endif

#define MAX_PATH_LEN 256
#define TASK_COMM_LEN 16

// Event types for user-space to distinguish
enum event_type {
   EVENT_LOOKUP = 1,
   EVENT_CREATE = 2,
};

struct file_collision_event {
    int type; // or u32
    int pid;  // or u32
    char comm[16];
    u32 uid;
    u32 gid;
    char requested_filename[256];
    char resolved_filename[256];
    bool case_mismatch;
    u64 inode_nr;
    u32 dev_id;
    bool operation_succeeded;
};

// User-space will set this to its own PID to filter out self-generated events
volatile const u32 self_pid = 0;

// Define a ring buffer map for sending events to user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Define a hash map to store context for kprobe -> kretprobe correlation
// Key: PID + thread ID (TGID)
// Value: The filename that was passed to the entry probe
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64); // tgid_pid
    __type(value, char[MAX_PATH_LEN]);
} op_args SEC(".maps");

// Kprobe on filename_lookup entry: Store the requested filename
SEC("kprobe/filename_lookup")
int BPF_KPROBE(kprobe_filename_lookup_entry, int dfd, const struct filename *name_arg, unsigned int flags, struct path *path_arg) {
   u64 tgid_pid = bpf_get_current_pid_tgid();
   u32 current_pid = tgid_pid >> 32;

   if (self_pid != 0 && current_pid == self_pid) {
       return 0;
   }
   bpf_printk("kprobe_filename_lookup_entry: pid %u, dfd %d, flags %u", current_pid, dfd, flags);

   char requested_name_component[MAX_PATH_LEN];
   __builtin_memset(requested_name_component, 0, sizeof(requested_name_component));

   if (!name_arg) {
       bpf_printk("kprobe_filename_lookup_entry: name_arg is NULL. Aborting.");
       return 0; 
   }

   const char *iname_ptr = NULL;
   const char *u_name_ptr = NULL; // Pointer for name_arg->name (userspace)
   bool stored = false;

   // 1. Try to read name_arg->iname (interned kernel string)
   bpf_core_read(&iname_ptr, sizeof(iname_ptr), &name_arg->iname);
   bpf_printk("kprobe_filename_lookup_entry: name_arg=%p, iname_ptr=%p", name_arg, iname_ptr);

   if (iname_ptr) {
       long read_len = bpf_probe_read_kernel_str(requested_name_component, sizeof(requested_name_component), iname_ptr);
       bpf_printk("kprobe_filename_lookup_entry: Read from iname_ptr: read_len=%ld, component='%s'", read_len, requested_name_component);
       
       if (read_len > 1) {
           if (bpf_map_update_elem(&op_args, &tgid_pid, requested_name_component, BPF_ANY) == 0) {
               bpf_printk("kprobe_filename_lookup_entry: STORED (from iname) '%s' for pid %llu", requested_name_component, tgid_pid);
               stored = true;
           } else {
               bpf_printk("kprobe_filename_lookup_entry: FAILED to store (from iname) for pid %llu", tgid_pid);
           }
       } else {
           bpf_printk("kprobe_filename_lookup_entry: read_len (from iname) was %ld (<=1), NOT storing.", read_len);
       }
   } else {
       bpf_printk("kprobe_filename_lookup_entry: iname_ptr is NULL.");
   }
   
   // 2. If not stored from iname_ptr, try name_arg->name (userspace pointer)
   if (!stored) {
       bpf_printk("kprobe_filename_lookup_entry: Not stored from iname. Trying name_arg->name (userspace).");
       
       // Read the userspace pointer value from name_arg->name
       bpf_core_read((void **)&u_name_ptr, sizeof(u_name_ptr), &name_arg->name);
       bpf_printk("kprobe_filename_lookup_entry: u_name_ptr=%p", u_name_ptr);

       if (u_name_ptr) {
           // Clear buffer again before user string read
           __builtin_memset(requested_name_component, 0, sizeof(requested_name_component));
           // EXPERIMENT: Use bpf_probe_read_str instead of bpf_probe_read_user_str
           long read_len = bpf_probe_read_str(requested_name_component, sizeof(requested_name_component), u_name_ptr);
           bpf_printk("kprobe_filename_lookup_entry: Read from u_name_ptr (using bpf_probe_read_str): read_len=%ld, component='%s'", read_len, requested_name_component);
           
           if (read_len > 1) {
               if (bpf_map_update_elem(&op_args, &tgid_pid, requested_name_component, BPF_ANY) == 0) {
                   bpf_printk("kprobe_filename_lookup_entry: STORED (from u_name_ptr) '%s' for pid %llu", requested_name_component, tgid_pid);
                   // stored = true; 
               } else {
                   bpf_printk("kprobe_filename_lookup_entry: FAILED to store (from u_name_ptr) for pid %llu", tgid_pid);
               }
           } else {
               bpf_printk("kprobe_filename_lookup_entry: read_len (from u_name_ptr using bpf_probe_read_str) was %ld (<=1), NOT storing.", read_len);
           }
       } else {
           bpf_printk("kprobe_filename_lookup_entry: u_name_ptr is NULL. Cannot get filename.");
       }
   }
   return 0;
}

// Kretprobe on filename_lookup exit: Process the result
SEC("kretprobe/filename_lookup")
int BPF_KRETPROBE(kretprobe_filename_lookup_exit, int ret_val) { // ret_val is the return value of filename_lookup
   u64 tgid_pid = bpf_get_current_pid_tgid();
   u32 current_pid = tgid_pid >> 32;

   // Filter out events from the detector's own process (consistency, though kprobe should catch it)
   if (self_pid != 0 && current_pid == self_pid) {
       return 0;
   }
   bpf_printk("kretprobe_filename_lookup_exit: pid %u, ret_val %d", current_pid, ret_val);

   char *requested_name_ptr;
   struct file_collision_event *event;

   requested_name_ptr = bpf_map_lookup_elem(&op_args, &tgid_pid);
   if (!requested_name_ptr) {
       bpf_printk("kretprobe_filename_lookup_exit: no stored args for pid %llu", tgid_pid);
       return 0; // No stored args, or already processed (e.g. by self_pid filter in kprobe)
   }
   // It's important to delete the element even if we might not submit an event,
   // to prevent map pollution if further checks fail.
   bpf_map_delete_elem(&op_args, &tgid_pid);
   bpf_printk("kretprobe_filename_lookup_exit: retrieved '%s' for pid %llu", requested_name_ptr, tgid_pid);


   // If requested_name_ptr points to an empty string (first char is null), skip
   if (requested_name_ptr[0] == '\0') {
       bpf_printk("kretprobe_filename_lookup_exit: requested_name_ptr is empty string for pid %llu", tgid_pid);
       return 0;
   }

   event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
   if (!event) {
       bpf_printk("BPF: ringbuf_reserve failed for pid %u", current_pid);
       return 0;
   }

   event->type = EVENT_LOOKUP;
   event->pid = current_pid; // Already have current_pid
   bpf_get_current_comm(&event->comm, sizeof(event->comm));

   struct task_struct *task = (struct task_struct *)bpf_get_current_task();
   if (task) {
       const struct cred *cred = NULL;
       bpf_core_read(&cred, sizeof(cred), &task->real_cred);
       if (cred) {
           bpf_core_read(&event->uid, sizeof(event->uid), &cred->uid);
           bpf_core_read(&event->gid, sizeof(event->gid), &cred->gid);
       }
   }

   __builtin_memcpy(event->requested_filename, requested_name_ptr, sizeof(event->requested_filename));

   event->operation_succeeded = (ret_val == 0); // filename_lookup returns 0 on success
   event->case_mismatch = false;
   event->inode_nr = 0;
   event->dev_id = 0;
   event->resolved_filename[0] = '\0';

   bpf_printk("kretprobe_filename_lookup_exit: submitting event for pid %llu, req_name '%s', success: %d",
       tgid_pid, event->requested_filename, event->operation_succeeded);
   bpf_printk("BPF: Event submitted for pid %d, type %d", event->pid, event->type); // <-- move this up
   bpf_ringbuf_submit(event, 0);
   return 0;
}

// Kprobe on vfs_create entry: Store the requested filename
SEC("kprobe/vfs_create")
int BPF_KPROBE(kprobe_vfs_create_entry, struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry, umode_t mode, bool excl) {
   u64 tgid_pid = bpf_get_current_pid_tgid();
   u32 current_pid = tgid_pid >> 32;

   // Filter out events from the detector's own process
   if (self_pid != 0 && current_pid == self_pid) {
       return 0;
   }
    bpf_printk("kprobe_vfs_create_entry: pid %u", current_pid); // Uncommented

   char requested_name[MAX_PATH_LEN];
    __builtin_memset(requested_name, 0, sizeof(requested_name));


   if (dentry) {
       const unsigned char *path_component_ptr = NULL;
       bpf_core_read(&path_component_ptr, sizeof(path_component_ptr), &dentry->d_name.name);

       if (path_component_ptr) {
           long read_len = bpf_probe_read_kernel_str(requested_name, sizeof(requested_name), path_component_ptr);
            if (read_len > 1) { // Ensure we read something more than just a null terminator
                if (bpf_map_update_elem(&op_args, &tgid_pid, requested_name, BPF_ANY) == 0) { // Check return
                    bpf_printk("kprobe_vfs_create_entry: stored '%s' for pid %llu", requested_name, tgid_pid); // Uncommented
                } else {
                    bpf_printk("kprobe_vfs_create_entry: FAILED to store '%s' for pid %llu", requested_name, tgid_pid);
                }
            } else {
                bpf_printk("kprobe_vfs_create_entry: read_len from dentry->d_name.name was %ld (<=1)", read_len);
            }
       } else {
           bpf_printk("kprobe_vfs_create_entry: dentry->d_name.name is NULL");
       }
   } else {
       bpf_printk("kprobe_vfs_create_entry: dentry is NULL");
   }
   return 0;
}

// Kretprobe on vfs_create exit: Process the result
SEC("kretprobe/vfs_create")
int BPF_KRETPROBE(kretprobe_vfs_create_exit, struct dentry *ret_dentry) {
   u64 tgid_pid = bpf_get_current_pid_tgid();
   u32 current_pid = tgid_pid >> 32;

    // Filter out events from the detector's own process (consistency)
   if (self_pid != 0 && current_pid == self_pid) {
       return 0;
   }
    bpf_printk("kretprobe_vfs_create_exit: pid %u, ret_dentry %p", current_pid, ret_dentry); // Uncommented


   char *requested_name_ptr;
   struct file_collision_event *event;

   requested_name_ptr = bpf_map_lookup_elem(&op_args, &tgid_pid);
   if (!requested_name_ptr) {
       bpf_printk("kretprobe_vfs_create_exit: no stored args for pid %llu", tgid_pid); // Added printk
       return 0;
   }
   bpf_map_delete_elem(&op_args, &tgid_pid);
   bpf_printk("kretprobe_vfs_create_exit: retrieved '%s' for pid %llu", requested_name_ptr, tgid_pid); // Added printk

   if (requested_name_ptr[0] == '\0') {
       bpf_printk("kretprobe_vfs_create_exit: requested_name_ptr is empty for pid %llu", tgid_pid); // Added printk
       return 0;
   }

   event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
   if (!event)
       return 0;

   event->type = EVENT_CREATE;
   event->pid = current_pid;
   bpf_get_current_comm(&event->comm, sizeof(event->comm));

   struct task_struct *task = (struct task_struct *)bpf_get_current_task();
   if (task) {
       const struct cred *cred = NULL;
       bpf_core_read(&cred, sizeof(cred), &task->real_cred);
       if (cred) {
           bpf_core_read(&event->uid, sizeof(event->uid), &cred->uid);
           bpf_core_read(&event->gid, sizeof(event->gid), &cred->gid);
       }
   }

   __builtin_memcpy(event->requested_filename, requested_name_ptr, sizeof(event->requested_filename));

   event->operation_succeeded = false;
   event->case_mismatch = false;
   event->inode_nr = 0;
   event->dev_id = 0;
   event->resolved_filename[0] = '\0';

   if (ret_dentry && !IS_ERR(ret_dentry)) {
       event->operation_succeeded = true;
       
       const unsigned char *resolved_path_component_ptr = NULL;
       bpf_core_read(&resolved_path_component_ptr, sizeof(resolved_path_component_ptr), &ret_dentry->d_name.name);

       if (resolved_path_component_ptr) {
           bpf_probe_read_kernel_str(event->resolved_filename, sizeof(event->resolved_filename), resolved_path_component_ptr);
       }

       struct inode *inode = BPF_CORE_READ(ret_dentry, d_inode);
       if (inode) {
           event->inode_nr = BPF_CORE_READ(inode, i_ino);
           event->dev_id = BPF_CORE_READ(inode, i_sb, s_dev);
       }

       // Case mismatch check (still a placeholder for robust in-BPF check)
       bool match = true;
       if (event->requested_filename[0] != '\0' && event->resolved_filename[0] != '\0') {
           #pragma unroll
           for (int i = 0; i < MAX_PATH_LEN; i++) {
               if (event->requested_filename[i] == '\0' && event->resolved_filename[i] == '\0') break;
               if (event->requested_filename[i] == '\0' || event->resolved_filename[i] == '\0') {
                   match = false; // Different lengths
                   break;
               }
               if (event->requested_filename[i] != event->resolved_filename[i]) {
                   match = false; // Different characters
                   break;
               }
           }
           if (!match) { // If different and a file was resolved
                // This is a simplification. User-space should do the definitive case check.
                event->case_mismatch = true;
           } else {
                event->case_mismatch = false;
           }
       } else {
           event->case_mismatch = false; // One or both names are empty
       }
   }
   bpf_printk("kretprobe_vfs_create_exit: submitting event for pid %llu, req_name '%s', success: %d", tgid_pid, event->requested_filename, event->operation_succeeded); // Ensure this is uncommented
    bpf_printk("BPF: Event submitted for pid %d, type %d", event->pid, event->type);
   bpf_ringbuf_submit(event, 0);

   return 0;
}

char LICENSE[] SEC("license") = "GPL";