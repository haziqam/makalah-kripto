import os
import sqlite3
from pathlib import Path
from umbral import PublicKey
from db import DB_PATH
from fastapi import WebSocket
import json


DATA_DIR = Path("server_data/files")
DATA_DIR.mkdir(parents=True, exist_ok=True)

# In-memory WebSocket connections indexed by username
active_websockets = {}

def login(username, password):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        return c.fetchone() is not None

def get_public_key(username):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT encryption_pk, verifying_pk FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if row:
            encryption_pk = PublicKey.from_bytes(row[0])
            verifying_pk = PublicKey.from_bytes(row[1])
            return encryption_pk, verifying_pk
        return None, None

def upload_encrypted_file(file_name, uploader_username, capsule_bytes, ciphertext_bytes):
    file_path = DATA_DIR / f"{uploader_username}__{file_name}"
    file_path.write_bytes(ciphertext_bytes)

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO files (file_name, uploader, capsule, ciphertext_path)
                     VALUES (?, ?, ?, ?)''',
                  (file_name, uploader_username, capsule_bytes, str(file_path)))
        conn.commit()

def grant_access(file_name, uploader_username, receiver_username, kfrag_bytes):
    print(f"Granting access to {receiver_username} for file {file_name}")

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT capsule, ciphertext_path FROM files WHERE file_name=? AND uploader=?",
                  (file_name, uploader_username))
        row = c.fetchone()
        if not row:
            print("File not found.")
            return

        capsule_bytes, ciphertext_path = row
        ciphertext = Path(ciphertext_path).read_bytes()

        # WebSocket push if receiver is connected
        if receiver_username in active_websockets:
            ws = active_websockets[receiver_username]
            try:
                ws_data = {
                    "file_name": file_name,
                    "uploader": uploader_username,
                    "kfrag": kfrag_bytes.hex(),
                    "capsule": capsule_bytes.hex(),
                    "ciphertext": ciphertext.hex()
                }
                ws.send_text(json.dumps(ws_data))
                print(f"Sent data to {receiver_username} via WebSocket.")
            except Exception as e:
                print(f"WebSocket send error: {e}")

        return kfrag_bytes, capsule_bytes, ciphertext

def register_websocket(username: str, websocket: WebSocket):
    active_websockets[username] = websocket

def unregister_websocket(username: str):
    if username in active_websockets:
        del active_websockets[username]
