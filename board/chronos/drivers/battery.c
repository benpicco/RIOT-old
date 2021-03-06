#include <stdint.h>
#include <cc430x613x.h>
#include <cc430-adc.h>

uint32_t battery_get_voltage(void) {
    uint32_t voltage;
    voltage = adc12_single_conversion(REFVSEL_1, ADC12SHT0_10, ADC12INCH_11);

    /* Ideally we have A11=0->AVCC=0V ... A11=4095(2^12-1)->AVCC=4V
     * --> (A11/4095)*4V=AVCC --> AVCC=(A11*4)/4095 */
    voltage = (voltage * 2 * 2 * 1000) / 4095;  
    return voltage;
}
