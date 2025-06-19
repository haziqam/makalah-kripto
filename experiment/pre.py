import secrets

# Group parameters (2048-bit MODP Group from RFC 3526)
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



def encrypt(plaintext, public_key, g, p):
    r = secrets.randbelow(q - 1) + 1
    c1 = (pow(g, r, p) * plaintext) % p
    c2 = pow(public_key, r, p)
    return (c1, c2), r


def re_encrypt(ciphertext_a, rk_ab, p):
    c1, c2 = ciphertext_a
    c2_re = pow(c2, rk_ab, p)
    return (c1, c2_re)


def decrypt(ciphertext, secret_key, p):
    a_inv = pow(secret_key, -1, q)
    c2_root = pow(ciphertext[1], a_inv, p)
    plaintext = (ciphertext[0] * pow(c2_root, -1, p)) % p
    return plaintext



# Key generation for Alice
a = secrets.randbelow(q - 1) + 1
PK_a = pow(g, a, p)

# Key generation for Bob
b = secrets.randbelow(q - 1) + 1
PK_b = pow(g, b, p)

# Re-encryption key RK_{A->B} = b * a^{-1} mod q
a_inv = pow(a, -1, q)
rk_ab = (b * a_inv) % q

# Message m ∈ G
k = secrets.randbelow(q - 1) + 1
m = pow(g, k, p)

# Encrypt for Alice
ciphertext_a, r = encrypt(m, PK_a, g, p)

# Re-encryption step: Ca → Cb
ciphertext_b = re_encrypt(ciphertext_a, rk_ab, p)

# Bob decrypts
m_recovered = decrypt(ciphertext_b, b, p)


# Output
print("Original message m: ", m)
print("Ciphertext (Alice): ", ciphertext_a)
print("Ciphertext (Bob):   ", ciphertext_b)
print("Decrypted by Bob:   ", m_recovered)
print("Correct:", m == m_recovered)
