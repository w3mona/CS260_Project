#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <stdint.h> // For uint32_t
typedef uint32_t u32;
typedef uint64_t u64;
#include <bpf/libbpf.h> // For ring_buffer functions
#include <inttypes.h>

// Define u32 before including the BPF skeleton header
typedef uint32_t u32;

#include "detector.bpf.h" // Adjusted include path for generated skeleton


// Event types for user-space to distinguish
enum event_type {
   EVENT_LOOKUP = 1,
   EVENT_CREATE = 2,
};


// Event structure must match the one in detector.bpf.c
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

// Libbpf print callback (optional, for libbpf internal messages)
int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    // You can filter by level if needed
    // if (level >= LIBBPF_WARNING) {
    //    return vfprintf(stderr, format, args);
    // }
    return vfprintf(stderr, format, args);
}

// Callback for processing events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz) {
printf("handle_event: got event of size %zu\n", data_sz);
   struct file_collision_event *e = data;

   printf("PID %d (%s) User %s (UID %u) Group %s (GID %u) -- ",
          e->pid, e->comm, get_username(e->uid), e->uid, get_groupname(e->gid), e->gid);

   const char *op_type_str = (e->type == EVENT_LOOKUP) ? "LOOKUP" : (e->type == EVENT_CREATE) ? "CREATE" : "UNKNOWN";

   if (e->operation_succeeded) {

        printf("%s: Requested '%s', Resolved/Created as '%s' (inode %" PRIu64 ", dev %u)\n", op_type_str, e->requested_filename, e->resolved_filename, e->inode_nr, e->dev_id);
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

   libbpf_set_print(libbpf_print_fn); // Set libbpf printer function

   signal(SIGINT, sig_handler);
   signal(SIGTERM, sig_handler);

   obj = detector_bpf__open(); // Open BPF application
   if (!obj) {
       fprintf(stderr, "Failed to open BPF object\n");
       return 1;
   }

   // Set the self_pid in BPF program's rodata section
   // This allows the BPF program to filter out its own events.
   obj->rodata->self_pid = getpid();

   err = detector_bpf__load(obj); // Load BPF program
   if (err) {
       fprintf(stderr, "Failed to load BPF object: %d (%s)\n", err, strerror(-err));
       detector_bpf__destroy(obj);
       return 1;
   }

   err = detector_bpf__attach(obj);
   if (err) {
       fprintf(stderr, "Failed to attach BPF programs: %d (%s)\n", err, strerror(-err));
       goto cleanup;
   }

   rb = ring_buffer__new(bpf_map__fd(obj->maps.events), handle_event, NULL, NULL);
   if (!rb) {
       err = -errno; // errno is set by ring_buffer__new on failure
       fprintf(stderr, "Failed to create ring buffer: %d (%s)\n", err, strerror(-err));
       goto cleanup;
   }

   printf("Successfully loaded and attached BPF programs. Monitoring filename_lookup and vfs_create...\n");
   printf("Press Ctrl-C to exit.\n");

   while (!exiting) {
       err = ring_buffer__poll(rb, 100); // Poll with a 100ms timeout
       if (err == -EINTR) { // Interrupted by signal
           err = 0;
           // exiting will be true due to sig_handler, loop will terminate
           continue;
       }
       if (err < 0) {
           fprintf(stderr, "Error polling ring buffer: %d (%s)\n", err, strerror(-err));
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
