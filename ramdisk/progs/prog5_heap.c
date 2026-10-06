#include <syscall.h>

int main() {
  size_t memory = _syscall1(13, 16);
  return 0;
}
