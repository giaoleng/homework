#ifndef SM4_H
#define SM4_H

#include <cstdint>
#include <vector>

class SM4 {
public:
    void set_key(const uint8_t key[16]);
    void encrypt(const uint8_t input[16], uint8_t output[16]);

private:
    uint32_t rk[32]; // 轮密钥

    uint32_t tau(uint32_t A);
    uint32_t L1(uint32_t B);
    uint32_t L2(uint32_t B);
    void key_expansion(const uint8_t key[16]);
    static const uint8_t Sbox[256];
    static const uint32_t FK[4];
    static const uint32_t CK[32];
};

#endif
