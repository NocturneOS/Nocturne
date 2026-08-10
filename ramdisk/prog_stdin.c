// #include <assert.h>
#include <file.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <syscall.h>

int main() {
  char ch;

  while (true) {
    int rd_bytes = read(FD_STDIN, 1, 1, &ch);

    if (rd_bytes == 0) {
      continue;
    }

    printf("%c", ch);

    flush(FD_STDOUT);

    if (ch == '0') {
      break;
    }
  }
}
