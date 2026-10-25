#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  void *mem1 = malloc(32);
  void *mem2 = malloc(64);
  void *mem3 = malloc(2048);
  void *mem4 = malloc(1024);
  void *mem5 = malloc(16384);

  memset(mem1, 0, 32);
  memset(mem2, 0, 64);
  memset(mem3, 0, 2048);
  memset(mem4, 0, 1024);
  memset(mem5, 0, 16384);

  printf("MEM1 = %p\n", mem1);
  printf("MEM2 = %p\n", mem2);
  printf("MEM3 = %p\n", mem3);
  printf("MEM4 = %p\n", mem4);
  printf("MEM5 = %p\n", mem5);

  return 0;
}
