// Generate Ec2b seed and corresponding xorpad (key)
// Heavily based on work done at https://github.com/khang06/genshinblkstuff

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <ctime>

#include <random>

#include "magic.h"

// These functions are not exported, so hackaround it
extern "C" void oqs_mhy128_enc_c(const uint8_t *plaintext, const void *_schedule, uint8_t *ciphertext);
extern "C" void oqs_mhy128_dec_c(const uint8_t *chiphertext, const void *_schedule, uint8_t *plaintext);

// UnityPlayer:$26EA90
void key_scramble(uint8_t* key) {
    uint8_t round_keys[11*16] = {0};
    for (int round = 0; round <= 10; round++) {
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 16; j++) {
                uint64_t idx = (round << 8) + (i*16) + j;
                round_keys[round * 16 + i] ^= aes_xorpad_table[idx] ^ stack_table[idx];
            }
        }
    }

    uint8_t chip[16];
    oqs_mhy128_enc_c(key, round_keys, chip);
    memcpy(key, chip, 16);
}

// UnityPlayer:$19DA40
void get_decrypt_vector(uint8_t* key, const uint8_t* crypt, uint64_t crypt_size, uint8_t* output, uint64_t output_size) {
    assert(output_size == 4096); // no support for other sizes here

    uint64_t val = 0xFFFFFFFFFFFFFFFF;
    for (int i = 0; i < crypt_size >> 3; i++) {
        val = ((uint64_t*)crypt)[i] ^ val;
    }

    auto* key_qword = (uint64_t*)key;
    auto mt = std::mt19937_64(key_qword[1] ^ 0xceac3b5a867837ac ^ val ^ key_qword[0]);
    for (uint64_t i = 0; i < output_size >> 3; i++)
        ((uint64_t*)output)[i] = mt();
}

int main()
{
    // First generate random key and data
    uint8_t key[16];
    uint8_t data[2048];

    srand(time(nullptr));
    for (unsigned char & i : key) {
        i = rand();
    }
    for (unsigned char & i : data) {
        i = rand();
    }

    // Write them to Ec2b file
    auto* ec2b = fopen("Ec2bSeed.bin", "wb");
    if (ec2b != nullptr) {
        fwrite("Ec2b", sizeof(uint32_t), 1, ec2b); // "Ec2b", non-terminated
        fwrite("\x10\0\0\0", sizeof(uint32_t), 1, ec2b); // 0x10, key length(?) or version
        fwrite(key, sizeof(key), 1, ec2b);
        fwrite("\x0\x8\0\0", sizeof(uint32_t), 1, ec2b); // 0x800, data length
        fwrite(data, sizeof(data), 1, ec2b);
        fclose(ec2b);
    } else {
        printf("Could not write seed file");
        return 100;
    }

    // Scramble key
    key_scramble(key);
    for (int i = 0; i < 16; i++) {
        key[i] ^= key_xor_table[i];
    }

    // Generate xorpad from scrambled key and data
    uint8_t xorpad[4096] = {};
    get_decrypt_vector(key, data, sizeof(data), xorpad, sizeof(xorpad));

    // Write key file
    auto* vector = fopen("Ec2bKey.bin", "wb");
    if (vector != nullptr) {
        fwrite(xorpad, sizeof(xorpad), 1, vector);
        fclose(vector);
    } else {
        printf("Could not write key file");
        return 101;
    }
}