#include <stdint.h>

// Xors an array of 16 bytes into a single byte
uint8_t xor_combine(uint8_t* input) {
    uint8_t ret = 0;
    for (int i = 0; i < 16; i++)
        ret ^= input[i];
    return ret;
}