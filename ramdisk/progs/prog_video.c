#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>

#define CHUNK_SIZE 8192

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

  size_t fd = _syscall1(SYS_VIDEO_ACQUIRE, (size_t)&video);

  uint32_t white[CHUNK_SIZE];

  memset(&white, 0xff, CHUNK_SIZE * sizeof(uint32_t));

  for (int i = 0; i < 1280 * 720; i += CHUNK_SIZE) {
    write(fd, &white, (video.bpp >> 3) * CHUNK_SIZE);
  }

  return 0;
}
