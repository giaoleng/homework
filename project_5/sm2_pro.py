# sm2_enhanced.py
import random
from gmssl import sm3, func
from concurrent.futures import ThreadPoolExecutor

# ------------------ 曲线参数 ------------------
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
G = (Gx, Gy)

# ------------------ Jacobian 坐标基础运算 ------------------
def inverse_mod(k, m): return pow(k, -1, m)

def point_to_jac(P):
    x, y = P
    return (x, y, 1)

def jac_to_affine(P):
    X, Y, Z = P
    if Z == 0: return (0, 0)
    zinv = inverse_mod(Z, p)
    z2inv = (zinv * zinv) % p
    z3inv = (z2inv * zinv) % p
    x = (X * z2inv) % p
    y = (Y * z3inv) % p
    return (x, y)

def jac_double(P):
    X, Y, Z = P
    A = (X * X) % p
    B = (Y * Y) % p
    C = (B * B) % p
    D = (2 * ((X + B) ** 2 - A - C)) % p
    E = (3 * A + a * pow(Z, 4, p)) % p
    F = (E * E) % p
    X3 = (F - 2 * D) % p
    Y3 = (E * (D - X3) - 8 * C) % p
    Z3 = (2 * Y * Z) % p
    return (X3, Y3, Z3)

def jac_add(P, Q):
    if P[2] == 0: return Q
    if Q[2] == 0: return P
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q
    Z1Z1 = pow(Z1, 2, p)
    Z2Z2 = pow(Z2, 2, p)
    U1 = (X1 * Z2Z2) % p
    U2 = (X2 * Z1Z1) % p
    S1 = (Y1 * Z2 * Z2Z2) % p
    S2 = (Y2 * Z1 * Z1Z1) % p
    if U1 == U2:
        return jac_double(P) if S1 == S2 else (1, 1, 0)
    H = (U2 - U1) % p
    R = (S2 - S1) % p
    H2 = (H * H) % p
    H3 = (H * H2) % p
    U1H2 = (U1 * H2) % p
    X3 = (R * R - H3 - 2 * U1H2) % p
    Y3 = (R * (U1H2 - X3) - S1 * H3) % p
    Z3 = (H * Z1 * Z2) % p
    return (X3, Y3, Z3)

def point_mul(k, P):
    R = (1, 1, 0)  # infinity
    Q = point_to_jac(P)
    while k:
        if k & 1: R = jac_add(R, Q)
        Q = jac_double(Q)
        k >>= 1
    return jac_to_affine(R)

# ------------------ 密钥生成 ------------------
def gen_keypair():
    d = random.randint(1, n - 1)
    return d, point_mul(d, G)

# ------------------ KDF ------------------
def kdf(Z, klen):
    ct = 1
    key = b''
    while len(key) < klen:
        msg = Z + ct.to_bytes(4, 'big')
        key += bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(msg)))
        ct += 1
    return key[:klen]

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

# ------------------ 并发加密/解密 ------------------
def encrypt(msg, P):
    k = random.randint(1, n - 1)
    with ThreadPoolExecutor() as exe:
        C1 = exe.submit(point_mul, k, G).result()
        x2, y2 = exe.submit(point_mul, k, P).result()
    x2b, y2b = x2.to_bytes(32, 'big'), y2.to_bytes(32, 'big')
    t = kdf(x2b + y2b, len(msg))
    if int.from_bytes(t, 'big') == 0:
        raise ValueError("KDF zero")
    C2 = bytes(m ^ t[i] for i, m in enumerate(msg))
    C3 = sm3.sm3_hash(func.bytes_to_list(x2b + msg + y2b))
    return C1, C2, C3

def decrypt(C, d):
    C1, C2, C3 = C
    x2, y2 = point_mul(d, C1)
    x2b, y2b = x2.to_bytes(32, 'big'), y2.to_bytes(32, 'big')
    t = kdf(x2b + y2b, len(C2))
    if int.from_bytes(t, 'big') == 0:
        raise ValueError("KDF zero")
    m = bytes(c ^ t[i] for i, c in enumerate(C2))
    u = sm3.sm3_hash(func.bytes_to_list(x2b + m + y2b))
    if u != C3:
        raise ValueError("C3 mismatch")
    return m

# ------------------ 测试 ------------------
if __name__ == "__main__":
    m = b"giao211877861118300357891357455986735853"
    d, P = gen_keypair()
    print("明文:", m)
    C = encrypt(m, P)
    print("密文:", C)
    print("解密:", decrypt(C, d))