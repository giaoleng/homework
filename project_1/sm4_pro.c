#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <immintrin.h>

#ifdef _MSC_VER
#define ALIGN(x) __declspec(align(x))
#else
#define ALIGN(x) __attribute__((aligned(x)))
#endif

typedef unsigned char  u8;
typedef unsigned long  u32;

/* ===== S 盒 ===== */
const u8 Sbox[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    /* ... 其余 240 个字节与原数组相同 ... */
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

/* ===== 系统常数 FK ===== */
const u32 systemFK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

/* ===== 固定参数 CK ===== */
const u32 fixedCK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    /* ... 其余 28 个常量与原数组相同 ... */
    0x484f565d, 0x646b7279
};

/* ===== SIMD 工具：32 位循环左移 ===== */
static inline __m128i rotateLeft32(__m128i x, int bits) {
    return _mm_or_si128(_mm_slli_epi32(x, bits),
                        _mm_srli_epi32(x, 32 - bits));
}

/* ==== 线性变换 L1（用于加密） ==== */
static inline __m128i linearL1_SIMD(__m128i a) {
    a = _mm_xor_si128(a, rotateLeft32(a, 2));
    a = _mm_xor_si128(a, rotateLeft32(a, 10));
    a = _mm_xor_si128(a, rotateLeft32(a, 18));
    a = _mm_xor_si128(a, rotateLeft32(a, 24));
    return a;
}

/* ==== 线性变换 L2（用于密钥扩展） ==== */
static inline __m128i linearL2_SIMD(__m128i a) {
    a = _mm_xor_si128(a, rotateLeft32(a, 13));
    a = _mm_xor_si128(a, rotateLeft32(a, 23));
    return a;
}

/* ==== S 盒变换（SIMD 版：拆包-查表-打包） ==== */
static inline __m128i sBoxTransform_SIMD(__m128i in) {
    ALIGN(16) u8 bytes[16];
    _mm_store_si128((__m128i*)bytes, in);
    for (int i = 0; i < 16; ++i) bytes[i] = Sbox[bytes[i]];
    return _mm_load_si128((__m128i*)bytes);
}

/* ==== 合成变换 T ==== */
static inline __m128i compositeT_SIMD(__m128i a, short mode) {
    __m128i b = sBoxTransform_SIMD(a);
    return (mode == 1) ? linearL1_SIMD(b) : linearL2_SIMD(b);
}

/* ===== 密钥扩展：第一步 ===== */
void extendFirst(u32 masterKey[4], u32 tempK[4]) {
    __m128i mk = _mm_loadu_si128((__m128i*)masterKey);
    __m128i fk = _mm_loadu_si128((__m128i*)systemFK);
    __m128i res = _mm_xor_si128(mk, fk);
    _mm_storeu_si128((__m128i*)tempK, res);
}

/* ===== 密钥扩展：第二步 ===== */
void extendSecond(u32 roundKey[32], u32 tempK[4]) {
    u32 localK[4];
    memcpy(localK, tempK, sizeof(u32) * 4);
    for (int i = 0; i < 32; ++i) {
        u32 inputVal = localK[(i + 1) % 4] ^
                       localK[(i + 2) % 4] ^
                       localK[(i + 3) % 4] ^
                       fixedCK[i];

        __m128i inputVec = _mm_set1_epi32(inputVal);
        __m128i resultVec = compositeT_SIMD(inputVec, 2); /* 模式2：L2 */
        u32 result = _mm_cvtsi128_si32(resultVec);

        localK[(i + 4) % 4] = localK[i % 4] ^ result;
        roundKey[i] = localK[(i + 4) % 4];
    }
}

/* ===== 生成 32 轮密钥 ===== */
void generateRoundKey(u32 masterKey[4], u32 tempK[4], u32 roundKey[32]) {
    extendFirst(masterKey, tempK);
    extendSecond(roundKey, tempK);
}

/* ===== 32 轮迭代（SIMD 版） ===== */
void iterate32_SIMD(u32 state[4], u32 roundKey[32]) {
    u32 local[4];
    memcpy(local, state, sizeof(u32) * 4);
    for (int i = 0; i < 32; ++i) {
        u32 inputVal = local[(i + 1) % 4] ^
                       local[(i + 2) % 4] ^
                       local[(i + 3) % 4] ^
                       roundKey[i];

        __m128i inputVec = _mm_set1_epi32(inputVal);
        __m128i resultVec = compositeT_SIMD(inputVec, 1); /* 模式1：L1 */
        u32 result = _mm_cvtsi128_si32(resultVec);

        local[(i + 4) % 4] = local[i % 4] ^ result;
    }
    /* 调整输出顺序：X35/X34/X33/X32 */
    state[0] = local[3];
    state[1] = local[2];
    state[2] = local[1];
    state[3] = local[0];
}

/* ===== 加密（SIMD 版） ===== */
void encryptSM4_SIMD(u32 plain[4], u32 roundKey[32], u32 cipher[4]) {
    u32 tmp[4];
    memcpy(tmp, plain, sizeof(u32) * 4);
    iterate32_SIMD(tmp, roundKey);
    memcpy(cipher, tmp, sizeof(u32) * 4);
}

/* ===== 解密（SIMD 版） ===== */
void decryptSM4_SIMD(u32 cipher[4], u32 roundKey[32], u32 plain[4]) {
    u32 invKey[32];
    for (int i = 0; i < 32; ++i) invKey[i] = roundKey[31 - i];

    u32 tmp[4];
    memcpy(tmp, cipher, sizeof(u32) * 4);
    iterate32_SIMD(tmp, invKey);
    memcpy(plain, tmp, sizeof(u32) * 4);
}

/* ===== 测试主函数 ===== */
int main(void) {
    u32 plain[4] = {0xdeadbeef, 0xc0ffee00, 0xfade0fad, 0x87654321};
    u32 key[4]        = {0x1337cafe, 0xbaadf00d, 0xdeadc0de, 0xfeedface};
    u32 roundKey[32];
    u32 tempK[4];
    long long loops = 1000000;

    /* 生成轮密钥 */
    generateRoundKey(key, tempK, roundKey);

    /* 性能计时 */
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    for (long long i = 0; i < loops; ++i) {
        u32 tmp[4];
        memcpy(tmp, plain, sizeof(u32) * 4);
        encryptSM4_SIMD(tmp, roundKey, tmp);
        decryptSM4_SIMD(tmp, roundKey, tmp);
    }

    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    printf("SM4 SIMD Performance Test\n");
    printf("========================\n");
    printf("Total time     : %.3f s\n", elapsed);
    printf("Avg per op     : %.2e s\n", elapsed / (loops * 4));

    return 0;
}