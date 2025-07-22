#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>    // 添加clock_t和clock()所需头文件
#include <stdlib.h>  // 添加malloc和free所需头文件

// SM3算法的初始向量(IV)
static const uint32_t IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

// 预计算的常量表，避免每次调用Tj函数
static const uint32_t TJ_CONST[2] = {0x79cc4519, 0x7a879d8a};

// 内联函数优化
static inline uint32_t RL(uint32_t a, uint8_t k) {
    return (a << k) | (a >> (32 - k));
}

static inline uint32_t FF(uint32_t X, uint32_t Y, uint32_t Z, uint8_t j) {
    return (j < 16) ? (X ^ Y ^ Z) : ((X & Y) | (X & Z) | (Y & Z));
}

static inline uint32_t GG(uint32_t X, uint32_t Y, uint32_t Z, uint8_t j) {
    return (j < 16) ? (X ^ Y ^ Z) : ((X & Y) | ((~X) & Z));
}

static inline uint32_t P0(uint32_t X) {
    return X ^ RL(X, 9) ^ RL(X, 17);
}

static inline uint32_t P1(uint32_t X) {
    return X ^ RL(X, 15) ^ RL(X, 23);
}

// 优化后的单块处理函数
void sm3_one_block(uint32_t *hash, const uint8_t *block) {
    uint32_t Wj0[68];
    uint32_t Wj1[64];
    uint32_t A = hash[0], B = hash[1], C = hash[2], D = hash[3];
    uint32_t E = hash[4], F = hash[5], G = hash[6], H = hash[7];
    
    // 加载消息块并转换字节序（大端序）
    for (int i = 0; i < 16; i++) {
        Wj0[i] = ((uint32_t)block[i*4] << 24) |
                 ((uint32_t)block[i*4+1] << 16) |
                 ((uint32_t)block[i*4+2] << 8) |
                 (uint32_t)block[i*4+3];
    }
    
    // 优化消息扩展：减少中间变量，展开部分循环
    for (int i = 16; i < 68; i++) {
        uint32_t tmp = Wj0[i-16] ^ Wj0[i-9] ^ RL(Wj0[i-3], 15);
        Wj0[i] = P1(tmp) ^ RL(Wj0[i-13], 7) ^ Wj0[i-6];
    }
    
    // 并行计算Wj1
    for (int i = 0; i < 64; i++) {
        Wj1[i] = Wj0[i] ^ Wj0[i+4];
    }
    
    // 优化压缩函数：减少临时变量，展开关键路径
    for (int j = 0; j < 64; j++) {
        uint32_t T = TJ_CONST[j >> 4]; // 使用预计算常量表
        uint32_t SS1 = RL(RL(A, 12) + E + RL(T, j % 32), 7);
        uint32_t SS2 = SS1 ^ RL(A, 12);
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + Wj1[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + Wj0[j];
        
        // 更新寄存器状态（减少数据依赖）
        D = C;
        C = RL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = RL(F, 19);
        F = E;
        E = P0(TT2);
    }
    
    // 更新哈希值
    hash[0] ^= A;
    hash[1] ^= B;
    hash[2] ^= C;
    hash[3] ^= D;
    hash[4] ^= E;
    hash[5] ^= F;
    hash[6] ^= G;
    hash[7] ^= H;
}

// 优化后的完整哈希计算
void sm3_hash(const uint8_t *data, size_t len, uint32_t *hash) {
    // 初始化哈希值
    memcpy(hash, IV, sizeof(IV));
    
    // 处理完整块
    size_t block_count = len / 64;
    for (size_t i = 0; i < block_count; i++) {
        sm3_one_block(hash, data + i * 64);
    }
    
    // 处理最后一个块
    size_t remaining = len % 64;
    uint8_t last_block[128] = {0}; // 最多需要两个块的空间
    size_t padding_start = remaining;
    
    // 复制剩余数据
    if (remaining > 0) {
        memcpy(last_block, data + block_count * 64, remaining);
    }
    
    // 添加填充位
    last_block[padding_start] = 0x80;
    padding_start++;
    
    // 如果剩余空间不足8字节（长度字段），需要额外块
    size_t total_bits = len * 8;
    if (remaining < 56) {
        // 当前块有足够空间
        last_block[63] = (uint8_t)(total_bits);
        last_block[62] = (uint8_t)(total_bits >> 8);
        last_block[61] = (uint8_t)(total_bits >> 16);
        last_block[60] = (uint8_t)(total_bits >> 24);
        last_block[59] = (uint8_t)(total_bits >> 32);
        last_block[58] = (uint8_t)(total_bits >> 40);
        last_block[57] = (uint8_t)(total_bits >> 48);
        last_block[56] = (uint8_t)(total_bits >> 56);
        sm3_one_block(hash, last_block);
    } else {
        // 需要两个块：填充块和长度块
        last_block[63] = 0; // 确保长度字段在第二个块
        sm3_one_block(hash, last_block);
        
        uint8_t length_block[64] = {0};
        length_block[63] = (uint8_t)(total_bits);
        length_block[62] = (uint8_t)(total_bits >> 8);
        length_block[61] = (uint8_t)(total_bits >> 16);
        length_block[60] = (uint8_t)(total_bits >> 24);
        length_block[59] = (uint8_t)(total_bits >> 32);
        length_block[58] = (uint8_t)(total_bits >> 40);
        length_block[57] = (uint8_t)(total_bits >> 48);
        length_block[56] = (uint8_t)(total_bits >> 56);
        sm3_one_block(hash, length_block);
    }
}

// 测试函数
void test_case(const char *test_name, const uint8_t *data, size_t len) {
    uint32_t hash[8];
    
    // 计时开始
    clock_t start = clock();
    sm3_hash(data, len, hash);
    clock_t end = clock();
    
    printf("%s: ", test_name);
    for (int i = 0; i < 8; i++) {
        printf("%08x ", hash[i]);
    }
    printf("\nTime: %.2f ms\n", (double)(end - start) * 1000 / CLOCKS_PER_SEC);
}

int main() {
    // 测试用例1: "abc"
    const uint8_t test1[] = {'a', 'b', 'c'};
    test_case("Test 1 (\"abc\")", test1, sizeof(test1));
    
    // 测试用例2: 64字节消息
    uint8_t test2[64];
    for (int i = 0; i < 64; i++) test2[i] = 'a' + (i % 26);
    test_case("Test 2 (64-byte)", test2, sizeof(test2));
    
    // 测试用例3: 长消息 (1MB)
    size_t long_len = 1024 * 1024;
    uint8_t *long_data = (uint8_t*)malloc(long_len);
    if (long_data) {
        memset(long_data, 0x61, long_len); // 全部填充'a'
        test_case("Test 3 (1MB)", long_data, long_len);
        free(long_data);
    }
    
    return 0;
}