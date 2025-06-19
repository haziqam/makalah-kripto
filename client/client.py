import base64
import json
import requests
import asyncio
import websockets
from pathlib import Path

from umbral import Capsule, SecretKey, Signer, PublicKey, CapsuleFrag
from umbral import encrypt, generate_kfrags, decrypt_reencrypted

SERVER_URL = "http://localhost:8000"
WS_URL = "ws://localhost:8000/ws"


async def login(username: str, password: str) -> bool:
    response = requests.post(f"{SERVER_URL}/login", json={"username": username, "password": password})
    if response.status_code == 200:
        print("Login successful.")
        asyncio.create_task(listen_for_access(username))
        return True
    print("Login failed.")
    print(response.content.decode())
    return False

def file_to_bytes(file_path: str) -> bytes:
    with open(file_path, "rb") as file:
        return file.read()

def upload_encrypted_file(uploader_username: str, file_name: str, file_bytes: bytes, pk: PublicKey):
    capsule, ciphertext = encrypt(pk, file_bytes)
    response = requests.post(f"{SERVER_URL}/upload", data={
        "file_name": file_name,
        "uploader_username": uploader_username
    }, files={
        "capsule": ("capsule.bin", capsule.to_bytes()),
        "ciphertext": ("ciphertext.bin", ciphertext)
    })
    if response.status_code == 200:
        print("File uploaded successfully.")
    else:
        print("Upload failed:", response.text)

def grant_access(
    receiver_username: str,
    file_name: str,
    delegating_sk: SecretKey,
    receiving_pk: PublicKey,
    signer: Signer
):
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
        "uploader_username": signer.verifying_key().to_bytes().hex(),
        "receiver_username": receiver_username,
        "kfrag": kfrag.to_bytes().hex()
    })
    if response.status_code == 200:
        print("Access granted.")
    else:
        print("Grant access failed:", response.text)

def get_public_key(username: str):
    response = requests.get(f"{SERVER_URL}/keys/{username}")
    if response.status_code == 200:
        data = response.json()
        enc_pk = PublicKey.from_bytes(base64.b64decode(data["encryption_pk"]))
        sig_pk = PublicKey.from_bytes(base64.b64decode(data["verifying_pk"]))
        return enc_pk, sig_pk
    else:
        raise Exception("Failed to fetch public keys")

def receive_file(cfrag_bytes: bytes, capsule: Capsule, ciphertext: bytes, uploader_username: str, receiver_username: str):
    cfrags = [CapsuleFrag.from_bytes(cfrag_bytes)]

    delegating_pk, verifying_pk = get_public_key(uploader_username)
    receiving_pk, _ = get_public_key(receiver_username)

    verified_cfrags = [
        cfrag.verify(
            capsule,
            verifying_pk=verifying_pk,
            delegating_pk=delegating_pk,
            receiving_pk=receiving_pk,
        )
        for cfrag in cfrags
    ]

    sk_hex = input("Enter your secret key (hex): ")
    receiving_sk = SecretKey.from_bytes(bytes.fromhex(sk_hex))

    cleartext = decrypt_reencrypted(
        receiving_sk=receiving_sk,
        delegating_pk=delegating_pk,
        capsule=capsule,
        verified_cfrags=verified_cfrags,
        ciphertext=ciphertext
    )

    print("Decrypted message:", cleartext.decode())

async def listen_for_access(username: str):
    async with websockets.connect(f"{WS_URL}/{username}") as websocket:
        print(f"Listening for granted file access as {username}...")
        while True:
            message = await websocket.recv()
            data = json.loads(message)
            print("Received re-encrypted file from:", data["uploader"])

            cfrag_bytes = bytes.fromhex(data["kfrag"])
            capsule = Capsule.from_bytes(bytes.fromhex(data["capsule"]))
            ciphertext = bytes.fromhex(data["ciphertext"])

            receive_file(cfrag_bytes, capsule, ciphertext, data["uploader"], username)


if __name__ == "__main__":
    result = asyncio.run(login("alice", "alice_password"))
    print(result)