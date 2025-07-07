#include "sm4.h"
#include <cstring>

const uint8_t SM4::Sbox[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
    0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    // ...（省略中间 Sbox 值）...
    0x48
};

const uint32_t SM4::FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

const uint32_t SM4::CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

uint32_t SM4::tau(uint32_t A) {
    uint8_t a[4] = {
        static_cast<uint8_t>(A >> 24),
        static_cast<uint8_t>(A >> 16),
        static_cast<uint8_t>(A >> 8),
        static_cast<uint8_t>(A)
    };
    for (int i = 0; i < 4; i++) {
        a[i] = Sbox[a[i]];
    }
    return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

uint32_t SM4::L1(uint32_t B) {
    return B ^ (B << 2 | B >> 30) ^ (B << 10 | B >> 22)
             ^ (B << 18 | B >> 14) ^ (B << 24 | B >> 8);
}

uint32_t SM4::L2(uint32_t B) {
    return B ^ (B << 13 | B >> 19) ^ (B << 23 | B >> 9);
}

void SM4::key_expansion(const uint8_t key[16]) {
    uint32_t K[36];
    for (int i = 0; i < 4; i++) {
        K[i] = (key[4*i] << 24) | (key[4*i+1] << 16) |
               (key[4*i+2] << 8) | key[4*i+3];
        K[i] ^= FK[i];
    }
    for (int i = 0; i < 32; i++) {
        uint32_t temp = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i];
        K[i+4] = K[i] ^ L2(tau(temp));
        rk[i] = K[i+4];
    }
}

void SM4::set_key(const uint8_t key[16]) {
    key_expansion(key);
}

void SM4::encrypt(const uint8_t input[16], uint8_t output[16]) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = (input[4*i] << 24) | (input[4*i+1] << 16) |
               (input[4*i+2] << 8) | input[4*i+3];
    }
    for (int i = 0; i < 32; i++) {
        uint32_t tmp = X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i];
        X[i+4] = X[i] ^ L1(tau(tmp));
    }
    for (int i = 0; i < 4; i++) {
        uint32_t B = X[35 - i];
        output[4*i]     = B >> 24;
        output[4*i + 1] = B >> 16;
        output[4*i + 2] = B >> 8;
        output[4*i + 3] = B;
    }
}
#include <iostream>
#include "sm4.h"

int main() {
    SM4 sm4;
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10
    };

    uint8_t plain[16] = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10
    };

    uint8_t cipher[16] = {0};

    sm4.set_key(key);
    sm4.encrypt(plain, cipher);

    std::cout << "Ciphertext: ";
    for (int i = 0; i < 16; i++)
        printf("%02x ", cipher[i]);
    std::cout << std::endl;

    return 0;
}
