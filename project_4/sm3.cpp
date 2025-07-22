#include<stdio.h>
#include<stdint.h>

// SM3算法的初始向量(IV)
static const uint32_t IV[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

// 根据轮数j返回常量Tj
uint32_t Tj(uint8_t j) {
    if (j < 16)
        return 0x79cc4519;  // 前16轮的常量
    return 0x7a879d8a;      // 后48轮的常量
}

// 布尔函数FF，根据轮数j选择不同的逻辑
uint32_t FF(uint32_t X, uint32_t Y, uint32_t Z, uint8_t j) {
    if (j < 16)
        return X ^ Y ^ Z;   // 前16轮使用异或
    return (X & Y) | (X & Z) | (Y & Z);  // 后48轮使用多数函数
}

// 布尔函数GG，根据轮数j选择不同的逻辑
uint32_t GG(uint32_t X, uint32_t Y, uint32_t Z, uint8_t j) {
    if (j < 16)
        return X ^ Y ^ Z;   // 前16轮使用异或
    return (X & Y) | ((~X) & Z);  // 后48轮使用选择函数
}

// 循环左移函数
uint32_t RL(uint32_t a, uint8_t k) {
    k = k % 32;  // 确保位移在0-31范围内
    return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k));
}

// 置换函数P0
uint32_t P0(uint32_t X) {
    return X ^ (RL(X, 9)) ^ (RL(X, 17));
}

// 置换函数P1
uint32_t P1(uint32_t X) {
    return X ^ (RL(X, 15)) ^ (RL(X, 23));
}

// 处理单个512位数据块的核心函数
void sm3_one_block(uint32_t *hash, const uint32_t *block) {
    uint32_t Wj0[68];  // 消息扩展后的132个字
    uint32_t Wj1[64];  // 压缩后的128个字
    uint32_t A = hash[0], B = hash[1], C = hash[2], D = hash[3];
    uint32_t E = hash[4], F = hash[5], G = hash[6], H = hash[7];
    uint32_t SS1, SS2, TT1, TT2;
    uint8_t i, j;

    // 步骤1: 消息扩展
    for (i = 0; i < 16; i++) {
        Wj0[i] = block[i];  // 将输入块分为16个字
    }
    for (i = 16; i < 68; i++) {
        // 扩展算法
        Wj0[i] = P1(Wj0[i - 16] ^ Wj0[i - 9] ^ RL(Wj0[i - 3], 15)) ^ RL(Wj0[i - 13], 7) ^ Wj0[i - 6];
    }
    for (i = 0; i < 64; i++) {
        // 生成压缩消息字
        Wj1[i] = Wj0[i] ^ Wj0[i + 4];
    }

    // 步骤2: 压缩函数，64轮迭代
    for (j = 0; j < 64; j++) {
        // 计算中间变量
        SS1 = RL((RL(A, 12) + E + RL(Tj(j), j)) & 0xFFFFFFFF, 7);
        SS2 = SS1 ^ (RL(A, 12));
        TT1 = (FF(A, B, C, j) + D + SS2 + Wj1[j]) & 0xFFFFFFFF;
        TT2 = (GG(E, F, G, j) + H + SS1 + Wj0[j]) & 0xFFFFFFFF;
        
        // 更新寄存器状态
        D = C;
        C = RL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = RL(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 步骤3: 更新哈希值（与原始IV进行异或）
    hash[0] = (A ^ hash[0]);
    hash[1] = (B ^ hash[1]);
    hash[2] = (C ^ hash[2]);
    hash[3] = (D ^ hash[3]);
    hash[4] = (E ^ hash[4]);
    hash[5] = (F ^ hash[5]);
    hash[6] = (G ^ hash[6]);
    hash[7] = (H ^ hash[7]);
}

// 完整的SM3哈希计算函数
void sm3_get_hash(uint32_t *src, uint32_t *hash, uint32_t len) {
    uint8_t last_block[64] = {0};  // 存储最后一个数据块
    uint32_t i = 0;
    
    // 初始化哈希值为IV
    for (i = 0; i < 8; i++) {
        hash[i] = IV[i];
    }
    
    // 处理完整的数据块
    for (i = 0; i < len; i = i + 64) {
        if (len - i < 64) break;  // 剩余数据不足一个完整块
        sm3_one_block(hash, src + i);  // 处理单个块
    }
    
    // 处理最后一个不完整的数据块
    uint32_t last_block_len = len - i;
    uint32_t word_len = ((last_block_len + 3) >> 2) << 2;  // 对齐到4字节边界
    uint32_t last_word_len = last_block_len & 3;  // 最后一个字中的字节数
    
    // 复制剩余数据到最后一个块
    for (int j = 0; j < word_len; j++)
        last_block[j] = *((uint8_t *) src + i + j);
    
    // 添加填充位'1'和必要的0
    switch (last_word_len) {
        case 0:
            last_block[word_len + 3] = 0x80;  // 0b10000000
            break;
        case 1:
            last_block[word_len - 4] = 0;
            last_block[word_len - 3] = 0;
            last_block[word_len - 2] = 0x80;
            break;
        case 2:
            last_block[word_len - 4] = 0;
            last_block[word_len - 3] = 0x80;
            break;
        case 3:
            last_block[word_len - 4] = 0x80;
            break;
        default:
            break;
    }
    
    // 处理填充和消息长度
    if (last_block_len < 56) {
        // 情况1: 当前块有足够空间添加长度信息
        uint32_t bit_len = len << 3;  // 计算消息的比特长度
        // 在块末尾添加64位长度信息（大端序）
        last_block[63] = (bit_len >> 24) & 0xff;
        last_block[62] = (bit_len >> 16) & 0xff;
        last_block[61] = (bit_len >> 8) & 0xff;
        last_block[60] = (bit_len) & 0xff;
        sm3_one_block(hash, (uint32_t *) last_block);
    } else {
        // 情况2: 需要额外的块存放长度信息
        sm3_one_block(hash, (uint32_t *) last_block);
        unsigned char lblock[64] = {0};
        uint32_t bit_len = len << 3;  // 计算消息的比特长度
        // 在第二个填充块中添加长度信息
        lblock[63] = (bit_len >> 24) & 0xff;
        lblock[62] = (bit_len >> 16) & 0xff;
        lblock[61] = (bit_len >> 8) & 0xff;
        lblock[60] = (bit_len) & 0xff;
        sm3_one_block(hash, (uint32_t *) lblock);
    }
}

// 测试用例1: 短消息"abc"
void test_case1() {
    uint32_t src[1] = {0x61626300};  // "abc"的十六进制表示
    uint32_t hash[8];
    uint32_t len = 3;  // 消息长度3字节
    
    sm3_get_hash(src, hash, len);
 
    printf("Test case 1 (\"abc\"): ");
    for (int i = 0; i < 8; i++) {
        printf("%08x ", hash[i]);
    }
    printf("\n");
}

// 测试用例2: 64字节的长消息
void test_case2() {
    // 包含16个0x61626364的字（即"abcd"重复64次）
    uint32_t src[16] = {0x61626364, 0x61626364, 0x61626364, 0x61626364, 
                        0x61626364, 0x61626364, 0x61626364, 0x61626364,
                        0x61626364, 0x61626364, 0x61626364, 0x61626364, 
                        0x61626364, 0x61626364, 0x61626364, 0x61626364};
    uint32_t hash[8];
    uint32_t len = 64;  // 消息长度64字节
    
    sm3_get_hash(src, hash, len);
 
    printf("Test case 2 (64-byte message): ");
    for (int i = 0; i < 8; i++) {
        printf("%08x ", hash[i]);
    }
    printf("\n");
}

int main() {
    test_case1();  // 运行测试用例1
    test_case2();  // 运行测试用例2
    return 0;
}