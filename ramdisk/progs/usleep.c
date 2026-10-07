#include <stdio.h>
#include <unistd.h>

int main() {
  int counter = 0;

  while (1) {
    printf("Counter: %d\n", counter);

    usleep(1000 * 1000); // 1 second

    counter++;
  }

  return 0;
}
