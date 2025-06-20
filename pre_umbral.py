from umbral import SecretKey, Signer

alices_secret_key = SecretKey.random()
alices_public_key = alices_secret_key.public_key()
print(alices_public_key)

alices_signing_key = SecretKey.random()
alices_verifying_key = alices_signing_key.public_key()
alices_signer = Signer(alices_signing_key)


from umbral import encrypt
plaintext = b'Proxy Re-encryption is cool!'
capsule, ciphertext = encrypt(alices_public_key, plaintext)

# Alice tries decrypting from ciphertext => works
from umbral import decrypt_original
cleartext = decrypt_original(alices_secret_key, capsule, ciphertext)


bobs_secret_key = SecretKey.random()
bobs_public_key = bobs_secret_key.public_key()

from umbral import generate_kfrags
kfrags = generate_kfrags(delegating_sk=alices_secret_key,
                          receiving_pk=bobs_public_key,
                          signer=alices_signer,
                          threshold=1,
                          shares=1)


import random
kfrags = random.sample(kfrags,  # All kfrags from above
                        1)      # M - Threshold


from umbral import reencrypt
cfrags = list()                 # Bob's cfrag collection
for kfrag in kfrags:
    cfrag = reencrypt(capsule=capsule, kfrag=kfrag)
    cfrags.append(cfrag)        # Bob collects a cfrag


from umbral import CapsuleFrag
suspicious_cfrags = [CapsuleFrag.from_bytes(bytes(cfrag)) for cfrag in cfrags]
cfrags = [cfrag.verify(capsule,
                        verifying_pk=alices_verifying_key,
                        delegating_pk=alices_public_key,
                        receiving_pk=bobs_public_key,
                        )
           for cfrag in suspicious_cfrags]

from umbral import decrypt_reencrypted

# Bob tries decrypting from cfrags => works
cleartext = decrypt_reencrypted(receiving_sk=bobs_secret_key,
                                 delegating_pk=alices_public_key,
                                 capsule=capsule,
                                 verified_cfrags=cfrags,
                                 ciphertext=ciphertext)

print(cleartext)



# # Step 1: Charlie's keypair
# charlies_secret_key = SecretKey.random()
# charlies_public_key = charlies_secret_key.public_key()

# # Step 2: Alice generates a kfrag for Charlie
# kfrags_charlie = generate_kfrags(
#     delegating_sk=alices_secret_key,
#     receiving_pk=charlies_public_key,
#     signer=alices_signer,
#     threshold=1,
#     shares=1
# )

# # Step 3: Proxy re-encrypts capsule for Charlie
# charlie_kfrag = random.choice(kfrags_charlie)
# charlie_cfrag = reencrypt(capsule=capsule, kfrag=charlie_kfrag)

# # Step 4: Charlie verifies the cfrag
# charlie_cfrag_verified = CapsuleFrag.from_bytes(bytes(charlie_cfrag)).verify(
#     capsule,
#     verifying_pk=alices_verifying_key,
#     delegating_pk=alices_public_key,
#     receiving_pk=charlies_public_key,
# )

# # Step 5: Charlie decrypts
# cleartext_charlie = decrypt_reencrypted(
#     receiving_sk=charlies_secret_key,
#     delegating_pk=alices_public_key,
#     capsule=capsule,
#     verified_cfrags=[charlie_cfrag_verified],
#     ciphertext=ciphertext
# )

# print("Charlie decrypted message:", cleartext_charlie.decode())
