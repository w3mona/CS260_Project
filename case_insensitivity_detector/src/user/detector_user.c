#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <bpf/libbpf.h> // For ring_buffer functions

#include "detector.bpf.h" // Adjusted include path for generated skeleton


// Event types for user-space to distinguish
enum event_type {
   EVENT_LOOKUP = 1,
   EVENT_CREATE = 2,
};


// Event structure must match the one in detector.bpf.c
struct file_collision_event {
   enum event_type type;
   pid_t pid;
   char comm[16];
   uid_t uid;
   gid_t gid;
   char requested_filename[256];
   char resolved_filename[256];
   bool case_mismatch;
   unsigned long long inode_nr;
   unsigned long long dev_id; // Changed to unsigned long long for dev_t compatibility
   bool operation_succeeded;
};


static volatile bool exiting = false;


static void sig_handler(int sig) {
   exiting = true;
}


static const char *get_username(uid_t uid) {
   struct passwd *pw = getpwuid(uid);
   return pw ? pw->pw_name : "(unknown)";
}


static const char *get_groupname(gid_t gid) {
   struct group *gr = getgrgid(gid);
   return gr ? gr->gr_name : "(unknown)";
}


// Callback for processing events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz) {
   struct file_collision_event *e = data;


   printf("PID %d (%s) User %s (UID %u) Group %s (GID %u) -- ",
          e->pid, e->comm, get_username(e->uid), e->uid, get_groupname(e->gid), e->gid);


   const char *op_type_str = (e->type == EVENT_LOOKUP) ? "LOOKUP" : (e->type == EVENT_CREATE) ? "CREATE" : "UNKNOWN";


   if (e->operation_succeeded) {
       printf("%s: Requested '%s', Resolved/Created as '%s' (inode %llu, dev %llu)\n", // Corrected dev_id format specifier
              op_type_str, e->requested_filename, e->resolved_filename, e->inode_nr, e->dev_id);
       if (e->case_mismatch) {
           printf("  *** CASE MISMATCH DETECTED ***: Requested '%s' vs Actual '%s'\n",
                  e->requested_filename, e->resolved_filename);
       }
   } else {
       printf("%s FAILED: Requested '%s'\n", op_type_str, e->requested_filename);
   }
   return 0;
}


int main(int argc, char **argv) {
   struct detector_bpf *obj;
   struct ring_buffer *rb = NULL;
   int err;


   signal(SIGINT, sig_handler);
   signal(SIGTERM, sig_handler);


   obj = detector_bpf__open_and_load();
   if (!obj) {
       fprintf(stderr, "Failed to open and load BPF object\n");
       return 1;
   }


   // Attach Kprobes for both vfs_lookup and vfs_create
   err = detector_bpf__attach(obj);
   if (err) {
       fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
       goto cleanup;
   }


   rb = ring_buffer__new(bpf_map__fd(obj->maps.events), handle_event, NULL, NULL);
   if (!rb) {
       fprintf(stderr, "Failed to create ring buffer: %d\n", -errno);
       goto cleanup;
   }


   printf("Successfully loaded and attached BPF programs. Monitoring vfs_lookup and vfs_create...\n");
   printf("Press Ctrl-C to exit.\n");


   while (!exiting) {
       err = ring_buffer__poll(rb, 100); // Poll with a timeout
       if (err == -EINTR) { // Interrupted by signal
           err = 0;
           continue; // Continue to check exiting flag
       }
       if (err < 0) {
           fprintf(stderr, "Error polling ring buffer: %d\n", err);
           break;
       }
       // No events means err == 0, loop continues
   }


cleanup:
   ring_buffer__free(rb);
   detector_bpf__destroy(obj);
   printf("Exiting.\n");
   return err != 0;
}
