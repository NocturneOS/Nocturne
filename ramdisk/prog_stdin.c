// #include <assert.h>
#include <file.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <syscall.h>

int main() {
  char ch;

  while (true) {
    read(FD_STDIN, 1, 1, &ch);

    printf("%c", ch);

    if (ch == '0') {
      break;
    }
  }
}
