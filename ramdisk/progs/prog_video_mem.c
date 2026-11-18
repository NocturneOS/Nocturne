#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>

struct videomode_info {
  uint32_t width;
  uint32_t height;

  uint8_t bpp;

  uint8_t red_offset;
  uint8_t green_offset;
  uint8_t blue_offset;

  uint64_t fb_addr;
};

int main() {
  struct videomode_info video;

  size_t fd = _syscall1(SYS_VIDEO_ACQUIRE, (size_t)&video);

  memset((uint8_t *)((size_t)video.fb_addr), 0xff,
         video.width * video.height * (video.bpp >> 3));

  return 0;
}
