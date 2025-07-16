# sm2_original.py
import random
from gmssl import sm3, func

# ------------------ 曲线参数 ------------------
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
G = (Gx, Gy)

# ------------------ 基础运算 ------------------
def inverse_mod(k, m): return pow(k, -1, m)

def point_add(P, Q):
    if P == (0, 0): return Q
    if Q == (0, 0): return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and y1 != y2: return (0, 0)
    if P != Q:
        lam = ((y2 - y1) * inverse_mod(x2 - x1, p)) % p
    else:
        lam = ((3 * x1 * x1 + a) * inverse_mod(2 * y1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def point_mul(k, P):
    R = (0, 0)
    while k:
        if k & 1: R = point_add(R, P)
        P = point_add(P, P)
        k >>= 1
    return R

# ------------------ 密钥生成 ------------------
def gen_keypair():
    d = random.randint(1, n - 1)
    return d, point_mul(d, G)

# ------------------ 签名/验签 ------------------
def hash_msg(msg): return int(sm3.sm3_hash(func.bytes_to_list(msg)), 16)

def sign(msg, d):
    e = hash_msg(msg)
    while True:
        k = random.randint(1, n - 1)
        x1, _ = point_mul(k, G)
        r = (e + x1) % n
        if r == 0 or r + k == n: continue
        s = (inverse_mod(1 + d, n) * (k - r * d)) % n
        if s != 0: return r, s

def verify(msg, sig, P):
    r, s = sig
    e = hash_msg(msg)
    t = (r + s) % n
    if t == 0: return False
    x1, _ = point_add(point_mul(s, G), point_mul(t, P))
    return (e + x1) % n == r

# ------------------ 测试 ------------------
if __name__ == "__main__":
    m = b"giao211877861118300357891357455986735853"
    d, P = gen_keypair()
    r, s = sign(m, d)
    print("签名: r =", hex(r), "s =", hex(s))
    print("验签结果:", verify(m, (r, s), P))