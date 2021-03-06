#ifndef _ARM_CPU_H
#define _ARM_CPU_H

#include <stdint.h>
#include "VIC.h"
#include "arm_common.h"

#define NEW_TASK_CPSR 0x1F
#define WORDSIZE 32

extern void dINT();
extern void eINT();

void thread_yield();
uint32_t get_system_speed(void);
void cpu_clock_scale(uint32_t source, uint32_t target, uint32_t* prescale);

void arm_reset(void);
void stdio_flush(void);

#endif // _ARM_CPU_H
