// #include <assert.h>
#include <file.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <syscall.h>

union event_value {
  struct {
    uint8_t code;
    bool pressed;
  } keyboard;

  struct {
    int32_t dx;
    int32_t dy;
  } mouse_move;

  struct {
    uint8_t button;
    bool pressed;
  } mouse_button;

  uint8_t mouse_wheel_direction;
} __attribute__((packed));

typedef struct {
  uint16_t kind;
  union event_value event;

  char _reserved[22];
} __attribute__((packed)) event_t;

#define static_assert _Static_assert
static_assert(sizeof(event_t) == 32, "event_t should be 32 bytes long");

int evq_open() { return _syscall1(14, 0); }

int main() {
  int fd = evq_open();

  event_t ev;

  while (true) {
    read(fd, 1, sizeof(ev), &ev);

    if (ev.kind == 0) {
      char key = ev.event.keyboard.code;

      if (ev.event.keyboard.pressed) {
        printf("Scancode: 0x%x\n", ev.event.keyboard.code);
      }
    }
  }

  close(fd);
}
