#include "vmlinux.h" // For kernel types
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#define MAX_PATH_LEN 256
#define TASK_COMM_LEN 16
// Event types for user-space to distinguish
enum event_type {
   EVENT_LOOKUP = 1,
   EVENT_CREATE = 2,
};
// Event structure
struct file_collision_event {
   enum event_type type; 
   pid_t pid;
   char comm[TASK_COMM_LEN];
   kuid_t uid;
   kgid_t gid;
   char requested_filename[MAX_PATH_LEN]; // The filename as requested by the user
   char resolved_filename[MAX_PATH_LEN]; // The actual filename found/created by the kernel
   bool case_mismatch;                   // True if requested_filename != resolved_filename (case-wise)
   u64 inode_nr;                        // Inode number of the resolved file/directory
   dev_t dev_id;                        // Device ID of the resolved file/directory
   bool operation_succeeded;             // True if vfs_lookup/vfs_create returned a valid dentry
};


// Define a ring buffer map for sending events to user-space
struct {
   __uint(type, BPF_MAP_TYPE_RINGBUF);
   __uint(max_entries, 256 * 1024); // Example size, must be power of 2
} events SEC(".maps");
// Define a hash map to store context for kprobe -> kretprobe correlation
// Key: PID + thread ID (TGID)
// Value: The filename that was passed to the entry probe
struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __uint(max_entries, 1024);
   __uint(key_size, sizeof(u64)); // tgid_pid
   __uint(value_size, MAX_PATH_LEN);
} op_args SEC(".maps"); // Renamed from lookup_args to be more generic


// Kprobe on vfs_lookup entry: Store the requested filename
SEC("kprobe/vfs_lookup")
int BPF_KPROBE(kprobe_vfs_lookup_entry, struct dentry *dir, struct qstr *name, unsigned int flags) {
   u64 tgid_pid = bpf_get_current_pid_tgid();
   char requested_name[MAX_PATH_LEN];
   // Read the requested filename (the component being looked up)
   bpf_probe_read_kernel_str(requested_name, sizeof(requested_name), name->name);
   // Store it in a map to retrieve in kretprobe
   bpf_map_update_elem(&op_args, &tgid_pid, requested_name, BPF_ANY);
   return 0;
}
// Kretprobe on vfs_lookup exit: Process the result
SEC("kretprobe/vfs_lookup")
int BPF_KRETPROBE(kretprobe_vfs_lookup_exit, struct dentry *ret_dentry) {
   u64 tgid_pid = bpf_get_current_pid_tgid();
   char *requested_name_ptr; // Pointer to the name stored in the map
   struct file_collision_event *event;
   // Retrieve the requested filename from the map
   requested_name_ptr = bpf_map_lookup_elem(&op_args, &tgid_pid);
   if (!requested_name_ptr) {
       return 0;
   }
   // Remove the entry from the map after retrieval to clean up
   bpf_map_delete_elem(&op_args, &tgid_pid);


   // Reserve space in the ring buffer for the event
   event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
   if (!event)
       return 0;
   // Populate common event fields
   event->type = EVENT_LOOKUP; // Set event type
   event->pid = tgid_pid >> 32;
   bpf_get_current_comm(&event->comm, sizeof(event->comm));
   struct task_struct *task = (struct task_struct *)bpf_get_current_task();
   BPF_CORE_READ_INTO(&event->uid, task, real_cred.uid);
   BPF_CORE_READ_INTO(&event->gid, task, real_cred.gid);
   bpf_probe_read_str(event->requested_filename, sizeof(event->requested_filename), requested_name_ptr);
   event->operation_succeeded = false;
   event->case_mismatch = false;
   event->inode_nr = 0;
   event->dev_id = 0;
   event->resolved_filename[0] = '\0'; // Initialize
   if (ret_dentry && !((long)ret_dentry > -MAX_ERRNO && (long)ret_dentry < 0)) {
       event->operation_succeeded = true;
       char resolved_name_from_dentry[MAX_PATH_LEN];
       bpf_probe_read_kernel_str(resolved_name_from_dentry, sizeof(resolved_name_from_dentry), ret_dentry->d_name.name);
       bpf_probe_read_str(event->resolved_filename, sizeof(event->resolved_filename), resolved_name_from_dentry);
       struct inode *inode = BPF_CORE_READ(ret_dentry, d_inode);
       if (inode) {
           event->inode_nr = BPF_CORE_READ(inode, i_ino);
           event->dev_id = BPF_CORE_READ(inode, i_sb, s_dev);
       }
       bool match = true;
       for (int i = 0; i < MAX_PATH_LEN; i++) {
           if (event->requested_filename[i] == '\0' && event->resolved_filename[i] == '\0') break;
           if (event->requested_filename[i] != event->resolved_filename[i]) {
               match = false;
               break;
           }
       }
       event->case_mismatch = !match;
   }
   bpf_ringbuf_submit(event, 0);
   return 0;
}
// Kprobe on vfs_create entry: Store the requested filename
SEC("kprobe/vfs_create")
int BPF_KPROBE(kprobe_vfs_create_entry, struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry, umode_t mode, bool excl) {
   u64 tgid_pid = bpf_get_current_pid_tgid();
   char requested_name[MAX_PATH_LEN];


   // Read the requested filename for creation
   bpf_probe_read_kernel_str(requested_name, sizeof(requested_name), dentry->d_name.name);


   // Store it in a map to retrieve in kretprobe
   bpf_map_update_elem(&op_args, &tgid_pid, requested_name, BPF_ANY);
   return 0;
}
// Kretprobe on vfs_create exit: Process the result
SEC("kretprobe/vfs_create")
int BPF_KRETPROBE(kretprobe_vfs_create_exit, struct dentry *ret_dentry) {
   u64 tgid_pid = bpf_get_current_pid_tgid();
   char *requested_name_ptr;
   struct file_collision_event *event;


   requested_name_ptr = bpf_map_lookup_elem(&op_args, &tgid_pid);
   if (!requested_name_ptr) {
       return 0;
   }
   bpf_map_delete_elem(&op_args, &tgid_pid);


   event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
   if (!event)
       return 0;


   event->type = EVENT_CREATE; // Set event type
   event->pid = tgid_pid >> 32;
   bpf_get_current_comm(&event->comm, sizeof(event->comm));
   struct task_struct *task = (struct task_struct *)bpf_get_current_task();
   BPF_CORE_READ_INTO(&event->uid, task, real_cred.uid);
   BPF_CORE_READ_INTO(&event->gid, task, real_cred.gid);
  
   bpf_probe_read_str(event->requested_filename, sizeof(event->requested_filename), requested_name_ptr);


   event->operation_succeeded = false;
   event->case_mismatch = false;
   event->inode_nr = 0;
   event->dev_id = 0;
   event->resolved_filename[0] = '\0'; // Initialize


   if (ret_dentry && !((long)ret_dentry > -MAX_ERRNO && (long)ret_dentry < 0)) {
       event->operation_succeeded = true;
      
       char resolved_name_from_dentry[MAX_PATH_LEN];
       bpf_probe_read_kernel_str(resolved_name_from_dentry, sizeof(resolved_name_from_dentry), ret_dentry->d_name.name);
       bpf_probe_read_str(event->resolved_filename, sizeof(event->resolved_filename), resolved_name_from_dentry);


       struct inode *inode = BPF_CORE_READ(ret_dentry, d_inode);
       if (inode) {
           event->inode_nr = BPF_CORE_READ(inode, i_ino);
           event->dev_id = BPF_CORE_READ(inode, i_sb, s_dev);
       }


       bool match = true;
       for (int i = 0; i < MAX_PATH_LEN; i++) {
           if (event->requested_filename[i] == '\0' && event->resolved_filename[i] == '\0') break;
           if (event->requested_filename[i] != event->resolved_filename[i]) {
               match = false;
               break;
           }
       }
       event->case_mismatch = !match;
   }
   bpf_ringbuf_submit(event, 0);
   return 0;
}
char LICENSE[] SEC("license") = "GPL";
