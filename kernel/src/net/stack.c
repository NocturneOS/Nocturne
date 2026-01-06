//
// Created by maractus on 04.01.24.
//

#include "net/cards.h"
#include "net/stack.h"
#include "lib/vector.h"
#include "mem/vmm.h"
#include <io/logging.h>
#include "sys/scheduler/scheduler.h"
#include "net/ethernet.h"

volatile vector_t* system_network_incoming_queue = 0;
volatile vector_t* system_network_outgoing_queue = 0;

void netstack_processor();
void netstack_processor_out();

void netstack_init() {
    system_network_incoming_queue = vector_new();
    system_network_outgoing_queue = vector_new();

	thread_create(get_current_proc(), netstack_processor, 0x1000, THREAD_KERNEL, NULL, 0);
	thread_create(get_current_proc(), netstack_processor_out, 0x1000, THREAD_KERNEL, NULL, 0);
}

void netstack_push(netcard_entry_t* card, void* packet_data, size_t length) {
	netqueue_item_t* item = kcalloc(sizeof(netqueue_item_t), 1);
	void* data = kcalloc(1, length);

	memcpy(data, packet_data, length);

	item->data = data;
	item->card = card;
	item->length = length;

	vector_push_back((vector_t*)system_network_outgoing_queue, (size_t) item);
}

void netstack_transfer(netcard_entry_t* card, void* packet_data, size_t length) {
	netqueue_item_t* item = kcalloc(sizeof(netqueue_item_t), 1);
	void* data = kcalloc(1, length);

	memcpy(data, packet_data, length);

	item->data = data;
	item->card = card;
	item->length = length;

	vector_push_back((vector_t*)system_network_incoming_queue, (size_t) item);
}


netqueue_item_t* netstack_pop() {
    netqueue_item_t* data = (void *) vector_pop_back((vector_t*)system_network_incoming_queue).element;

    return data;
}

netqueue_item_t* netstack_poll() {
    while(system_network_incoming_queue->size == 0) {
		__asm__ volatile("hlt");
		yield();
	}

    return netstack_pop();
}

void netstack_processor_out() {
	qemu_note("OUTGOING NETWORK QUEUE IS WORKING NOW!");

	while(1) {
		for(int i = system_network_outgoing_queue->size; i > 0; i--) {
			qemu_log("%d packets remaining", i);

			netqueue_item_t* item = (void*)vector_pop_back((vector_t*)system_network_outgoing_queue).element;
			item->card->send_packet(item->data, item->length);
		}

        yield();
	}
}

void netstack_processor() {
	qemu_note("NETWORK QUEUE IS WORKING NOW!");

	while(1) {
		qemu_note("WAITING FOR PACKET");
		netqueue_item_t* item = netstack_poll();
	
		qemu_note("RECEIVED PACKET");
		// item->card->send_packet(item->data, item->length);

		ethernet_handle_packet(item->card, item->data, item->length);

		qemu_ok("PACKET HANDLING FINISHED!");
	}
}
