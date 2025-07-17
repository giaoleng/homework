# P1_client.py
import socket
import pickle
import random
import hashlib
import gmpy2
from gmpy2 import mpz, powmod

# 定义群参数
prime = mpz(gmpy2.next_prime(2**127))  # 素数 p
generator = mpz(3)  # 生成元 g

# 定义哈希函数
def hash_function(x):
    digest = hashlib.sha256(str(x).encode()).hexdigest()
    return mpz(int(digest, 16)) % prime

# 客户端 P1 的输入数据
P1_data = ["alice", "bob", "carol"]
secret_key = random.randint(1, prime - 1)  # 私钥 k1

# 建立与服务器的连接
client_socket = socket.socket()
client_socket.connect(('localhost', 6666))

# 计算 Z = H(v)^k1，打乱顺序并发送
Z_values = [powmod(hash_function(v), secret_key, prime) for v in P1_data]
random.shuffle(Z_values)
client_socket.sendall(pickle.dumps(Z_values))
print("[P1] 发送 Z 值完成")

# 接收 Z2、公钥和 P2 的加密对组
received_data = pickle.loads(client_socket.recv(40960))
Z2_values, public_key, P2_pairs = received_data
print("[P1] 接收 Z2 和加密对组完成")

# 对每个 H(w)^k2 进行幂运算，并检查是否属于 Z2
intersection_ciphertexts = []
for hw_k2, ciphertext in P2_pairs:
    hw_k1k2 = powmod(hw_k2, secret_key, prime)
    if hw_k1k2 in Z2_values:
        intersection_ciphertexts.append(ciphertext)

# 同态加密求和
if intersection_ciphertexts:
    ciphertext_sum = intersection_ciphertexts[0]
    for ciphertext in intersection_ciphertexts[1:]:
        ciphertext_sum = ciphertext_sum + ciphertext
else:
    ciphertext_sum = public_key.encrypt(0)

# 发送 AEnc(S_J) 给 P2
client_socket.sendall(pickle.dumps(ciphertext_sum))
print("[P1] 发送 AEnc(S_J) 完成")
client_socket.close()