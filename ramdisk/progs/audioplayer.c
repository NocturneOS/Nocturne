#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <syscall.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "No file specified!\n");
    exit(1);
  }

  char *filename = argv[1];

  FILE *fp = fopen(filename, "rb");

  if (fp == NULL) {
    fprintf(stderr, "Failed to open the file!\n");
    return -ENOMEM;
  }

  size_t sz = fseek(fp, 0, SEEK_END);

  fseek(fp, 0, SEEK_SET);

  char *buffer = malloc(sz);

  if (buffer == NULL) {
    fprintf(stderr, "Failed to allocate the buffer!");
    return -ENOMEM;
  }

  fread(buffer, 1, sz, fp);

  const int BLOCK_SIZE = 16 << 10;

  {
    _syscall1(SYS_AUDIO_OPEN, 0);

    for (size_t played = 0; played < sz; played += BLOCK_SIZE) {
      _syscall3(SYS_AUDIO_WRITE, 0, (size_t)(buffer + played), BLOCK_SIZE);
    }

    _syscall1(SYS_AUDIO_CLOSE, 0);
  }

  free(buffer);
  fclose(fp);
}
