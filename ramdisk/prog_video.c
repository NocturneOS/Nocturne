#include <file.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>

struct videomode_info {
  uint32_t width;
  uint32_t height;

  uint8_t bpp;

  uint8_t red_offset;
  uint8_t green_offset;
  uint8_t blue_offset;
};

int main() {
  struct videomode_info video;

  size_t fd = _syscall1(20, (size_t)&video);

#define CHUNK_SIZE 8192

  uint32_t white[CHUNK_SIZE];

  memset(&white, 0xff, CHUNK_SIZE * sizeof(uint32_t));

  for (int i = 0; i < 1280 * 720; i += CHUNK_SIZE) {
    write(fd, 1, (video.bpp >> 3) * CHUNK_SIZE, &white);
  }

  return 0;
}
