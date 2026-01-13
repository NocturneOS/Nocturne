/**
 * @file sys/isr.c
 * @author Пиминов Никита (nikita.piminoff@yandex.ru), NDRAEY
 * @brief Обработчик прерывания высокого уровня
 * @version 0.4.3
 * @date 2022-10-01
 * @copyright Copyright SayoriOS Team (c) 2022-2026
 */

#include "arch/x86/isr.h"
#include "sys/apic.h"
#include <arch/x86/ports.h>
#include <io/logging.h>
#include "sys/cpu_isr.h"

volatile isr_t interrupt_handlers[256];

extern size_t* stack_top;

void isr_handler(registers_t regs) {
    isr_t handler = interrupt_handlers[regs.int_num];

    if(handler != NULL) {
        handler(&regs);
    }
}

void irq_handler(registers_t regs) {
    isr_t handler = interrupt_handlers[regs.int_num];

    irq_eoi(regs.int_num);

    if (handler != 0) {        
        handler(&regs);
    }
}

void irq_eoi(size_t int_nr) {
    if(__using_apic) {
        apic_write(0xB0, 0x00);
    } else {
        if (int_nr >= 0x28){
            outb(0xA0, 0x20);
        }

        outb(0x20, 0x20);
    }
}

/* @param n - Номер обработчика */
/* @param handler - Функция обработчик */
void register_interrupt_handler(uint8_t n, isr_t handler) {
    interrupt_handlers[n] = handler;
    
    qemu_warn("Updated handler for IRQ %d", n);
}

/* Инициализация ISR */
void isr_init() {
    register_interrupt_handler(INT_0, &division_by_zero);
    register_interrupt_handler(INT_6, &fault_opcode);
    register_interrupt_handler(INT_8, &double_error);
    register_interrupt_handler(INT_10, &invalid_tss);
    register_interrupt_handler(INT_11, &segment_is_not_available);
    register_interrupt_handler(INT_12, &stack_error);
    register_interrupt_handler(INT_13, &general_protection_error);
    register_interrupt_handler(INT_14, &page_fault);
    register_interrupt_handler(INT_16, &fpu_fault);
}
