#include <io/screen.h>
#include <multiboot.h>
#include <sys/timer.h>
#include <io/logging.h>
#include <common.h>
#include "mem/pmm.h"
#include "mem/vmm.h"

#ifdef NOCTURNE_X86
#include "arch/x86/mtrr.h"
#endif

#include "sys/sync.h"

uint8_t *framebuffer_addr = 0;			/// Указатель на кадровый буфер экрана
volatile size_t framebuffer_pitch;				/// Частота обновления экрана
volatile size_t framebuffer_bpp;				/// Глубина цвета экрана
volatile size_t framebuffer_width;				/// Длина экрана
volatile size_t framebuffer_height;			/// Высота экрана
volatile size_t framebuffer_size;				/// Кол-во пикселей
uint8_t *back_framebuffer_addr = 0;		/// Позиция буфера экрана

size_t fb_mtrr_idx = 0;
size_t bfb_mtrr_idx = 0;

/**
 * @brief Получение адреса расположения драйвера экрана
 *
 * @return size_t - Адрес расположения
 */
size_t getDisplayAddr(){
    return (size_t)framebuffer_addr;
}

size_t getFrameBufferAddr() {
    return (size_t)back_framebuffer_addr;
}

/**
 * @brief Получение частоты обновления экрана
 *
 * @return uint32_t - Частота обновления
 */
uint32_t getDisplayPitch(){
    return framebuffer_pitch;
}

/**
 * @brief Получение глубины цвета экрана
 *
 * @return uint32_t - Глубина цвета
 */
uint32_t getDisplayBpp(){
    return framebuffer_bpp;
}

void create_back_framebuffer() {
    // back_framebuffer_addr = framebuffer_addr;

    qemu_log("^---- 1. Allocating");
    
    back_framebuffer_addr = (uint8_t*)kmalloc_common(framebuffer_size, PAGE_SIZE);

    qemu_log("^---- 2. Zeroing (%p - %p)", back_framebuffer_addr, back_framebuffer_addr + framebuffer_size);
    memset(back_framebuffer_addr, 0, framebuffer_size);

    qemu_ok("^---- Ready!");

    size_t phys_bfb = virt2phys(get_kernel_page_directory(), (virtual_addr_t) back_framebuffer_addr);

    qemu_log("Physical is: %x", phys_bfb);

    #ifdef NOCTURNE_ARCH_X86
	bfb_mtrr_idx = find_free_mtrr();
    write_mtrr_size(bfb_mtrr_idx, phys_bfb, framebuffer_size, 1);

	phys_set_flags(get_kernel_page_directory(), (virtual_addr_t)back_framebuffer_addr, PAGE_WRITEABLE | PAGE_CACHE_DISABLE);
    #endif
	
    qemu_log("framebuffer_size = %d (%dK) (%dM)", framebuffer_size, framebuffer_size/1024, framebuffer_size/(1024*1024));
    qemu_log("back_framebuffer_addr = %p", back_framebuffer_addr);
}

/**
 * @brief Инициализация графики
 *
 * @param mboot - информация полученная от загрузчика
 */
void init_vbe(const multiboot_header_t *mboot) {
    framebuffer_addr = (uint8_t *)(size_t)mboot->framebuffer_addr;
    framebuffer_pitch = mboot->framebuffer_pitch;
    framebuffer_bpp = mboot->framebuffer_bpp;
    framebuffer_width = mboot->framebuffer_width;
    framebuffer_height = mboot->framebuffer_height;

    framebuffer_size = framebuffer_height * framebuffer_pitch;

    qemu_log("[VBE] [USING LEGACY INFO] Width: %d; Height: %d; Pitch: %d; BPP: %d; Size: %d; Address: %x",
             mboot->framebuffer_width,
             mboot->framebuffer_height,
             mboot->framebuffer_pitch,
             mboot->framebuffer_bpp,
             mboot->framebuffer_height * mboot->framebuffer_pitch,
             (size_t)mboot->framebuffer_addr
    );
    
    physical_addr_t frame = (physical_addr_t)framebuffer_addr;
    virtual_addr_t virt = (virtual_addr_t)framebuffer_addr;

	map_pages(get_kernel_page_directory(),
			  frame,
			  virt,
			  framebuffer_size,
			  PAGE_WRITEABLE | PAGE_CACHE_DISABLE);

    qemu_log("Okay mapping!");

    create_back_framebuffer();

    qemu_log("Created back framebuffer");

    #ifdef NOCTURNE_ARCH_X86
	fb_mtrr_idx = find_free_mtrr();

    write_mtrr_size(fb_mtrr_idx, frame, framebuffer_size, 1);
    #endif
}

/**
 * @brief Получить цвет на пикселе по X и Y
 *
 * @param x - X
 * @param y - Y
 *
 * @return uint32_t - Цвет
 */
size_t getPixel(int32_t x, int32_t y){
    if (x < 0 || y < 0 ||
			x >= (int) VESA_WIDTH ||
        y >= (int) VESA_HEIGHT) {
        return 0x000000;
    }

    size_t where = x * (framebuffer_bpp >> 3) + y * framebuffer_pitch;

    return ((back_framebuffer_addr[where+2] & 0xff) << 16) + ((back_framebuffer_addr[where+1] & 0xff) << 8) + (back_framebuffer_addr[where] & 0xff);
}

void rgba_blend(uint8_t result[4], const uint8_t fg[4], const uint8_t bg[4])
{
    uint32_t alpha = fg[3] + 1;
    uint32_t inv_alpha = 256 - fg[3];

    result[0] = (uint8_t)((alpha * fg[0] + inv_alpha * bg[0]) >> 8);
    result[1] = (uint8_t)((alpha * fg[1] + inv_alpha * bg[1]) >> 8);
    result[2] = (uint8_t)((alpha * fg[2] + inv_alpha * bg[2]) >> 8);
    result[3] = 0xff;
}

/**
 * @brief Получение длины экрана
 *
 * @return uint32_t - длина
 */
uint32_t getScreenWidth(){
    return framebuffer_width;
}


/**
 * @brief Получение ширины экрана
 *
 * @return uint32_t - ширина
 */
uint32_t getScreenHeight(){
    return framebuffer_height;
}

void graphics_update(uint32_t new_width, uint32_t new_height, uint32_t new_pitch) {
    unmap_pages_overlapping(get_kernel_page_directory(), (virtual_addr_t)framebuffer_addr, framebuffer_size);

    framebuffer_width = new_width;
    framebuffer_height = new_height;
    framebuffer_pitch = new_pitch;
    framebuffer_bpp = (new_pitch / new_width) << 3;

    framebuffer_size = ALIGN((new_width + 32) * new_height * 4, PAGE_SIZE);

    map_pages(get_kernel_page_directory(),
              (physical_addr_t)framebuffer_addr,
              (virtual_addr_t)framebuffer_addr,
              framebuffer_size,
              PAGE_WRITEABLE | PAGE_CACHE_DISABLE
    );


    //back_framebuffer_addr = krealloc(back_framebuffer_addr, framebuffer_size);
    //memset(back_framebuffer_addr, 0x00, framebuffer_size);
   kfree(back_framebuffer_addr);
  back_framebuffer_addr = kmalloc_common(framebuffer_size, PAGE_SIZE);
  memset(back_framebuffer_addr, 0, framebuffer_size);

  #ifdef NOCTURNE_ARCH_X86
	phys_set_flags(get_kernel_page_directory(), (virtual_addr_t)back_framebuffer_addr, PAGE_WRITEABLE | PAGE_CACHE_DISABLE);

    uint32_t bfb_new_phys = virt2phys(get_kernel_page_directory(), (virtual_addr_t)back_framebuffer_addr);

    write_mtrr_size(fb_mtrr_idx, (uint32_t)framebuffer_addr, framebuffer_size, 1);
    write_mtrr_size(bfb_mtrr_idx, (uint32_t)bfb_new_phys, framebuffer_size, 1);
    #endif
}

#ifdef NOCTURNE_X86
    #ifdef __SSE2__
        #include <emmintrin.h>
    #endif
#endif

/**
 * @brief Очистка экрана
 *
 */
__attribute__((force_align_arg_pointer)) void clean_screen() {
// #ifdef __SSE2__
#if 0
  if((size_t)back_framebuffer_addr % 16 == 0) {
    __m128i* buffer = (__m128i*)back_framebuffer_addr;

    for(size_t index = 0, chunks = framebuffer_size / sizeof(__m128i); index < chunks; index ++) {
        _mm_store_si128(buffer, _mm_setzero_si128());

        buffer++;
    }
  } else {
    memset(back_framebuffer_addr, 0, framebuffer_size);
  }
#else
    //memset(back_framebuffer_addr, 0, framebuffer_size);
    __builtin_memset(back_framebuffer_addr, 0, framebuffer_size);
#endif
}

atomic_flag graphics_flush_mutex = ATOMIC_FLAG_INIT;

__attribute__((force_align_arg_pointer)) void screen_update() {
// #ifdef __SSE2__
    spinlock_get(&graphics_flush_mutex);
#if 0
    if((size_t)back_framebuffer_addr % 16 == 0) {
        __m128i* src_buffer = (__m128i*)back_framebuffer_addr;
        __m128i* dest_buffer = (__m128i*)framebuffer_addr;

        for(size_t index = 0, chunks = framebuffer_size / sizeof(__m128i); index < chunks; index ++) {
            _mm_store_si128(dest_buffer++, _mm_load_si128(src_buffer++));
        }
    } else {
        memcpy(framebuffer_addr, back_framebuffer_addr, framebuffer_size);
    }
#else
    memcpy(framebuffer_addr, back_framebuffer_addr, framebuffer_size);
    // __builtin_memcpy(framebuffer_addr, back_framebuffer_addr, framebuffer_size);
#endif
    spinlock_release(&graphics_flush_mutex);
}
