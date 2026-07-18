#include <memory.h>
#include <string.h>
#include <syscall.h>

int open(const char *path, int mode) {
  return _syscall2(SYS_OPEN, (size_t)path, (size_t)mode);
}

int read(int fd, int size, void *buffer) {
  return _syscall3(SYS_READ, (size_t)fd, (size_t)buffer, (size_t)size);
}

int write(int fd, int size, const void *buffer) {
  return _syscall3(SYS_WRITE, (size_t)fd, (size_t)buffer, (size_t)size);
}

void close(int fd) { _syscall1(SYS_CLOSE, (size_t)fd); }

int main() {
  int fd = open("mem0:/README", 1); // OMO_OPEN

  char *memory = sbrk(64);

  read(fd, 63, memory);

  close(fd);

  write(1, 63, memory);

  return 0;
}
