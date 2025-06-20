import base64
import requests

from umbral import Capsule, SecretKey, Signer, PublicKey, CapsuleFrag
from umbral import encrypt, generate_kfrags, decrypt_reencrypted

SERVER_URL = "http://localhost:8000"
WS_URL = "ws://localhost:8000/ws"


def login(username: str, password: str) -> bool:
    response = requests.post(f"{SERVER_URL}/login", json={"username": username, "password": password})
    if response.status_code != 200:
        print("Login failed.")
        return False

    print("Login successful.")
    return True


def get_public_key(username: str) -> tuple[PublicKey, PublicKey] | tuple[None, None]:
    response = requests.get(f"{SERVER_URL}/keys/{username}")
    if response.status_code == 200:
        data = response.json()
        enc_pk = PublicKey.from_bytes(base64.b64decode(data["encryption_pk"]))
        sig_pk = PublicKey.from_bytes(base64.b64decode(data["verifying_pk"]))
        return enc_pk, sig_pk
    else:
        print("Failed to fetch public key")
        return None, None

def file_to_bytes(file_path: str) -> bytes:
    with open(file_path, "rb") as file:
        return file.read()

def upload_file(uploader_username: str, file_path: str, file_name: str):
    file_bytes = file_to_bytes(file_path)
    pk, _ = get_public_key(uploader_username)

    if not pk:
        return

    capsule, ciphertext = encrypt(pk, file_bytes)

    response = requests.post(f"{SERVER_URL}/upload", data={
        "file_name": file_name,
        "uploader_username": uploader_username
    }, files={
        "capsule": ("capsule.bin", bytes(capsule)),
        "ciphertext": ("ciphertext.bin", ciphertext)
    })

    if response.status_code == 200:
        print("File uploaded successfully.")
    else:
        print("Upload failed:", response.text)

def grant_access(
    uploader_username: str,
    receiver_username: str,
    file_name: str,
    delegating_sk: SecretKey,
    signer: Signer
):
    receiving_pk, _ = get_public_key(receiver_username)

    if not receiving_pk:
        return

    kfrags = generate_kfrags(
        delegating_sk=delegating_sk,
        receiving_pk=receiving_pk,
        signer=signer,
        threshold=1,
        shares=1
    )
    kfrag = next(iter(kfrags))

    response = requests.post(f"{SERVER_URL}/grant", json={
        "file_name": file_name,
        "uploader_username": uploader_username,
        "receiver_username": receiver_username,
        "kfrag": base64.b64encode(bytes(kfrag)).decode()
    })

    if response.status_code == 200:
        print("Access granted.")
    else:
        print("Grant access failed:", response.text)

def access_file(file_name: str, uploader_username: str, receiver_username: str, receiving_sk: SecretKey):
    uploader_encryption_pk, uploader_signing_pk = get_public_key(uploader_username)
    receiver_pk, _ = get_public_key(receiver_username)

    response = requests.post(f"{SERVER_URL}/access-file", json={
        "file_name": file_name,
        "uploader_username": uploader_username,
        "receiver_username": receiver_username
    })

    if response.status_code != 200:
        print("Failed to access file:", response.text)
        return

    data = response.json()
    cfrag = CapsuleFrag.from_bytes(base64.b64decode(data["cfrag"]))
    capsule = Capsule.from_bytes(base64.b64decode(data["capsule"]))
    ciphertext = base64.b64decode(data["ciphertext"])

    verified_cfrag = cfrag.verify(capsule,
                        verifying_pk=uploader_signing_pk,
                        delegating_pk=uploader_encryption_pk,
                        receiving_pk=receiver_pk,
                        )

    decrypted_bytes = decrypt_reencrypted(
        receiving_sk=receiving_sk,
        delegating_pk=uploader_encryption_pk,
        capsule=capsule,
        verified_cfrags=[verified_cfrag],
        ciphertext=ciphertext
    )

    # for now, just print the decrypted file
    print("Decrypted file content:", decrypted_bytes.decode())

def fixed_secret(label):
        return SecretKey.from_bytes(label.ljust(32, b'_'))


if __name__ == "__main__":
    # On Alice's Machine
    alice_username = "alice"
    alice_password = "alice_password"
    alice_encryption_sk = fixed_secret(b"alice_encryption_sk")
    alice_signing_sk = fixed_secret(b"alice_signing_sk")

    login(alice_username, alice_password)

    upload_file("alice", "alice/hello.txt", "hello.txt")

    grant_access("alice", "bob", "hello.txt", alice_encryption_sk, Signer(alice_signing_sk))

    # On Bob's Machine
    bob_username = "bob"
    bob_password = "bob_password"
    
    login(bob_username, bob_password)
    bob_encryption_sk = fixed_secret(b"bob_encryption_sk")
    bob_signing_sk = fixed_secret(b"bob_signing_sk")

    access_file("hello.txt", "alice", "bob", bob_encryption_sk)

