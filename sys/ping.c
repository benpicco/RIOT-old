#include <stdio.h>
#include <stdlib.h>
#include <thread.h>
#include <msg.h>

#include "drivers/cc110x/cc1100.h"
#include "lpc2387.h"

#include "swtimer.h"
#include "gpioint.h"
#include <ping.h>

ping_payload *pipa;
protocol_t protocol_id = 0;
radio_address_t r_address = 0;
uint64_t start = 0;
float rtt = 0;

void ping_handler(void *payload, int payload_size, 
					packet_info_t *packet_info){
	pong(packet_info->phy_src);
}

void pong_handler(void *payload, int payload_size,
					packet_info_t *packet_info){
	calc_rtt();
	print_success();
}

void pong(uint16_t src){
	int trans_ok = cc1100_send_csmaca(src,protocol_id,2,pipa->payload,
			sizeof(pipa->payload));
	if(trans_ok < 0)
		print_failed();	
}

void ping_init(protocol_t protocol, uint8_t channr, radio_address_t addr){
	protocol_id = protocol;
	r_address = addr;
	cc1100_set_packet_handler(protocol, ping_handler);
	cc1100_set_channel(channr);
	cc1100_set_address(r_address);
	init_payload();
}

void ping(radio_address_t addr, uint8_t channr){
	cc1100_set_packet_handler(protocol_id, pong_handler);
	cc1100_set_channel(channr);
	cc1100_set_address(r_address);
	while(1){
		start = swtimer_now();
		int trans_ok = cc1100_send_csmaca(addr,
			protocol_id,2,pipa->payload,sizeof(pipa->payload));
		if(trans_ok < 0)
			print_failed();
		ktimer_wait(500000);
	}
}

void calc_rtt(){
	uint64_t end = swtimer_now();
	
	rtt = ((float)end - (float)start)/1000;	
}

void print_success(void){
	printf("%s%f%s\n","time=",rtt,"ms");
}

void print_failed(void){
	printf("%s\n","ping failed");
}

void init_payload(void){
	pipa = malloc(sizeof(pipa));
	pipa->payload = NULL;
}
