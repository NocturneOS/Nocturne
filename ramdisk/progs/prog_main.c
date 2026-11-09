#include <stdio.h>

int main(int argc, char **argv, char **envp) {
  printf("argc = %d\n", argc);
  printf("argv = %p\n", argv);

  for (int i = 0; i < argc; ++i) {
    printf("argv[%d] = `%s`\n", i, argv[i]);
  }

  printf("envp = %p\n", envp);

  return 0;
}
