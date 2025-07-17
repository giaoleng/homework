# P2_server.py
import socket
import pickle
import random
import hashlib
import gmpy2
from gmpy2 import mpz, powmod
from phe import paillier

# 定义群参数
prime = mpz(gmpy2.next_prime(2**127))  # 素数 p
generator = mpz(3)  # 生成元 g

# 定义哈希函数
def hash_function(x):
    digest = hashlib.sha256(str(x).encode()).hexdigest()
    return mpz(int(digest, 16)) % prime

# 服务端 P2 的输入数据
P2_data = [("bob", 10), ("carol", 20), ("dave", 30)]
secret_key = random.randint(1, prime - 1)  # 私钥 k2
pubkey, privkey = paillier.generate_paillier_keypair()

# 启动 socket 服务
server_socket = socket.socket()
server_socket.bind(('localhost', 6666))
server_socket.listen(1)
print("[P2] 等待 P1 连接...")

conn, _ = server_socket.accept()
print("[P2] 已连接 P1")

# 1. 接收 Z = H(v)^k1 的打乱列表
Z_values = pickle.loads(conn.recv(40960))
print("[P2] 收到 Z，数量:", len(Z_values))

# 2. 对 Z 中元素做幂运算：Z2 = Z^k2
Z2_values = [powmod(z, secret_key, prime) for z in Z_values]

# 3. 对 P2 自己的数据做处理：H(w)^k2 + AEnc(t)
P2_pairs = []
for w, t in P2_data:
    hw_k2 = powmod(hash_function(w), secret_key, prime)
    ct = pubkey.encrypt(t)
    P2_pairs.append((hw_k2, ct))

# 4. 打包并发送 Z2, pubkey, P2_pairs 给 P1
conn.sendall(pickle.dumps((Z2_values, pubkey, P2_pairs)))
print("[P2] 发送 Z2 和加密对组完成")

# 5. 接收 AEnc(S_J)
ct_sum = pickle.loads(conn.recv(40960))
S_J = privkey.decrypt(ct_sum)
print("[P2] 解密得到交集值总和 S_J =", S_J)

conn.close()