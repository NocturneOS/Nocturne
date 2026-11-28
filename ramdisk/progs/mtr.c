#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <syscall.h>

#define METRIC_MEMORY_USAGE (1 << 0)
#define METRIC_PROCESS_INFO (1 << 1)

struct metric_header {
  uint8_t id;
  uint16_t size;
} __attribute__((packed));

size_t getmetrics(size_t pid, uint32_t flags, void *buffer, size_t bufsize) {
  size_t res =
      _syscall5(SYS_GETMETRICS, pid, flags, 0, (size_t)buffer, bufsize);

  return res;
}

int main() {
  char buf[256];

  size_t got =
      getmetrics(-1, METRIC_MEMORY_USAGE | METRIC_PROCESS_INFO, buf, 256);

  printf("Got %d metrics.\n", got);

  char *cursor = buf;

  for (size_t i = 0; i < got; i++) {
    struct metric_header *hdr = (struct metric_header *)(cursor);

    printf("[%d] HDR: id: %hhu; size: %hu\n", i, hdr->id, hdr->size);

    if (hdr->id == 0) {
      struct memory_metric {
        uint64_t heap_used;
        uint32_t system_total;
        uint32_t system_free;
      };

      struct memory_metric *mem =
          (struct memory_metric *)(cursor + sizeof(struct metric_header));

      printf("Memory:\n");
      printf("\tHeap used: %" PRIu64 " bytes\n", mem->heap_used);
      printf("\tTotal system RAM: %" PRIu32 " pages\n", mem->system_total);
      printf("\tFree system RAM: %" PRIu32 " pages\n", mem->system_free);
    } else if (hdr->id == 1) {
      struct processinfo_metric {
        uint64_t pid;
        uint64_t thread_count;
      };

      struct processinfo_metric *proc =
          (struct processinfo_metric *)(cursor + sizeof(struct metric_header));

      printf("Process info\n");
      printf("\tPID: %" PRIu64 "\n", proc->pid);
      printf("\tThread count: %" PRIu64 "\n", proc->thread_count);
    }

    cursor += sizeof(struct metric_header) + hdr->size;
  }

  return 0;
}
