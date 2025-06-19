import secrets
from hashlib import sha256
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

# ---- GROUP SETUP (RFC 3526 Group 14) ----

p = int("""
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
FFFFFFFF FFFFFFFF
""".replace(" ", "").replace("\n", ""), 16)
g = 2
q = (p - 1) // 2

# ---- BBS ENCRYPTION ----

def encrypt_group_element(m, public_key, g, p):
    r = secrets.randbelow(q - 1) + 1
    c1 = (pow(g, r, p) * m) % p
    c2 = pow(public_key, r, p)
    return (c1, c2), r

def decrypt_group_element(ciphertext, secret_key, p):
    c1, c2 = ciphertext
    a_inv = pow(secret_key, -1, q)
    c2_root = pow(c2, a_inv, p)
    plaintext = (c1 * pow(c2_root, -1, p)) % p
    return plaintext

def re_encrypt(ct_k_sym, rk_ab, p):
    c1, c2 = ct_k_sym
    c2_re = pow(c2, rk_ab, p)  # (g^{ar})^{b/a} = g^{br}
    return (c1, c2_re)

# ---- AES ENCRYPTION ----

def aes_encrypt(plaintext: bytes, key: bytes):
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv, ciphertext, tag

def aes_decrypt(iv, ciphertext, tag, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ---- KEY GENERATION ----

a = secrets.randbelow(q - 1) + 1
PK_a = pow(g, a, p)

b = secrets.randbelow(q - 1) + 1
PK_b = pow(g, b, p)

a_inv = pow(a, -1, q)
rk_ab = (b * a_inv) % q

# ---- HYBRID ENCRYPTION ----

# 1. Generate symmetric key as group element (k_sym)
x = secrets.randbelow(q - 1) + 1
k_sym = pow(g, x, p)  # ∈ G

# 2. Encrypt k_sym with BBS encryption (for Alice)
ct_k_sym, r = encrypt_group_element(k_sym, PK_a, g, p)

# 3. Derive AES key from k_sym
aes_key = sha256(str(k_sym).encode()).digest()  # 256-bit key

# 4. Encrypt actual message with AES
message = b"Haziq"
iv, ct_data, tag = aes_encrypt(message, aes_key)

# --- TRANSFER + RE-ENCRYPTION ---
ct_k_sym_re = re_encrypt(ct_k_sym, rk_ab, p)

# Bob decrypts
k_sym_bob = decrypt_group_element(ct_k_sym_re, b, p)
aes_key_bob = sha256(str(k_sym_bob).encode()).digest()
decrypted_msg = aes_decrypt(iv, ct_data, tag, aes_key_bob)

# ---- OUTPUT ----

print("Original message:       ", message)
print("Decrypted by Bob:       ", decrypted_msg)
print("Correct decryption?     ", decrypted_msg == message)
