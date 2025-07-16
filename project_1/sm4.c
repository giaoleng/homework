#include<stdio.h>
#include <windows.h>
#define u8 unsigned char
#define u32 unsigned long

/* 非线性置换表 S 盒 */
const u8 Sbox[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    /* …… 其余字节省略 …… */
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

/* 系统常数 FK */
const u32 FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

/* 固定参数 CK */
const u32 CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    /* …… 其余常量省略 …… */
    0x484f565d, 0x646b7279
};

/* 函数原型 */
u32 functionB(u32 b);
u32 loopLeft(u32 a, short length);
u32 functionL1(u32 a);
u32 functionL2(u32 a);
u32 functionT(u32 a, short mode);
void extendFirst(u32 MK[], u32 K[]);
void extendSecond(u32 RK[], u32 K[]);
void getRK(u32 MK[], u32 K[], u32 RK[]);
void iterate32(u32 X[], u32 RK[]);
void reverse(u32 X[], u32 Y[]);
void encryptSM4(u32 X[], u32 RK[], u32 Y[]);
void decryptSM4(u32 X[], u32 RK[], u32 Y[]);

/* 查 S 盒 */
u32 functionB(u32 b) {
    u8 a[4];
    a[0] = b >> 24;
    a[1] = (b >> 16) & 0xFF;
    a[2] = (b >> 8) & 0xFF;
    a[3] = b & 0xFF;
    b = ((u32)Sbox[a[0]] << 24) |
        ((u32)Sbox[a[1]] << 16) |
        ((u32)Sbox[a[2]] << 8)  |
        (u32)Sbox[a[3]];
    return b;
}

/* 循环左移 */
u32 loopLeft(u32 a, short length) {
    for (short i = 0; i < length; ++i)
        a = (a << 1) | (a >> 31);
    return a;
}

/* 线性变换 L */
u32 functionL1(u32 a) {
    return a ^ loopLeft(a, 2) ^ loopLeft(a, 10) ^
           loopLeft(a, 18) ^ loopLeft(a, 24);
}

/* 线性变换 L' */
u32 functionL2(u32 a) {
    return a ^ loopLeft(a, 13) ^ loopLeft(a, 23);
}

/* 合成变换 T */
u32 functionT(u32 a, short mode) {
    return (mode == 1) ? functionL1(functionB(a)) : functionL2(functionB(a));
}

/* 密钥扩展第一步：K = MK ^ FK */
void extendFirst(u32 MK[], u32 K[]) {
    for (int i = 0; i < 4; ++i)
        K[i] = MK[i] ^ FK[i];
}

/* 密钥扩展第二步：生成 32 轮轮密钥 */
void extendSecond(u32 RK[], u32 K[]) {
    for (short i = 0; i < 32; ++i) {
        u32 tmp = K[(i + 1) % 4] ^ K[(i + 2) % 4] ^
                  K[(i + 3) % 4] ^ CK[i];
        K[(i + 4) % 4] = K[i % 4] ^ functionT(tmp, 2);
        RK[i] = K[(i + 4) % 4];
    }
}

/* 完整密钥扩展 */
void getRK(u32 MK[], u32 K[], u32 RK[]) {
    extendFirst(MK, K);
    extendSecond(RK, K);
}

/* 32 轮迭代 */
void iterate32(u32 X[], u32 RK[]) {
    for (short i = 0; i < 32; ++i) {
        u32 tmp = X[(i + 1) % 4] ^ X[(i + 2) % 4] ^
                  X[(i + 3) % 4] ^ RK[i];
        X[(i + 4) % 4] = X[i % 4] ^ functionT(tmp, 1);
    }
}

/* 反转顺序 */
void reverse(u32 X[], u32 Y[]) {
    for (short i = 0; i < 4; ++i)
        Y[i] = X[3 - i];
}

/* 加密 */
void encryptSM4(u32 X[], u32 RK[], u32 Y[]) {
    iterate32(X, RK);
    reverse(X, Y);
}

/* 解密 */
void decryptSM4(u32 X[], u32 RK[], u32 Y[]) {
    u32 reverseRK[32];
    for (short i = 0; i < 32; ++i)
        reverseRK[i] = RK[31 - i];

    iterate32(X, reverseRK);
    reverse(X, Y);
}

int main(void) {
    u32 plain[4];   
    u32 key[4];     
    u32 rk[32];     
    u32 ktmp[4];    
    u32 cipher[4];  
    u32 verify[4];  

    printf("Enter 128-bit plaintext (8 hex numbers, e.g., 01234567 89abcdef ...):\n");
    scanf_s("%8x%8x%8x%8x", &plain[0], &plain[1], &plain[2], &plain[3]);

    printf("Enter 128-bit key (8 hex numbers):\n");
    scanf_s("%8x%8x%8x%8x", &key[0], &key[1], &key[2], &key[3]);

        LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);

    getRK(key, ktmp, rk);
    printf("\n======== Round Keys ========\n");
    for (short i = 0; i < 32; ++i) {
        printf("RK[%2d] = %08x  ", i, rk[i]);
        if ((i + 1) % 4 == 0) printf("\n");
    }

    encryptSM4(plain, rk, cipher);
    printf("\n======== Encryption Result ========\n");
    printf("Ciphertext: %08x %08x %08x %08x\n", cipher[0], cipher[1], cipher[2], cipher[3]);

    decryptSM4(cipher, rk, verify);
    printf("\n======== Decryption Result ========\n");
    printf("Plaintext: %08x %08x %08x %08x\n", verify[0], verify[1], verify[2], verify[3]);

    QueryPerformanceCounter(&t2);
    double elapsed = (double)(t2.QuadPart - t1.QuadPart) / (double)freq.QuadPart;
    printf("\nTotal time elapsed: %.6f seconds\n", elapsed);

    return 0;
}