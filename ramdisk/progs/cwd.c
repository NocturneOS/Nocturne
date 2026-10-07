#include <stdio.h>
#include <stdlib.h>

int main() {
  char cwd[128] = {0};

  getcwd(cwd, 128);

  printf("`%s`\n", cwd);

  return 0;
}
