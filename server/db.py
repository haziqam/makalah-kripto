import sqlite3
from pathlib import Path
from umbral import PublicKey, SecretKey

DB_PATH = Path("server_data") / "db.sqlite3"

DB_PATH.parent.mkdir(parents=True, exist_ok=True)

if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT,
        encryption_pk BLOB,
        verifying_pk BLOB
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_name TEXT,
        uploader TEXT,
        capsule BLOB,
        ciphertext_path TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS file_permission (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER,
        receiver TEXT,
        cfrag BLOB,
        FOREIGN KEY(file_id) REFERENCES file(id),
        FOREIGN KEY(receiver) REFERENCES users(username)
    )''')

    def fixed_secret(label):
        return SecretKey.from_bytes(label.ljust(32, b'_'))

    alice_encryption_sk = fixed_secret(b"alice_encryption_sk")
    alice_signing_sk = fixed_secret(b"alice_signing_sk")
    bob_encryption_sk = fixed_secret(b"bob_encryption_sk")
    bob_signing_sk = fixed_secret(b"bob_signing_sk")
    carol_encryption_sk = fixed_secret(b"carol_encryption_sk")
    carol_signing_sk = fixed_secret(b"carol_signing_sk")
    dave_encryption_sk = fixed_secret(b"dave_encryption_sk")
    dave_signing_sk = fixed_secret(b"dave_signing_sk")

    users = [
        ('alice', 'alice_password', bytes(alice_encryption_sk.public_key()), bytes(alice_signing_sk.public_key())),
        ('bob', 'bob_password', bytes(bob_encryption_sk.public_key()), bytes(bob_signing_sk.public_key())),
        ('carol', 'carol_password', bytes(carol_encryption_sk.public_key()), bytes(carol_signing_sk.public_key())),
        ('dave', 'dave_password', bytes(dave_encryption_sk.public_key()), bytes(carol_signing_sk.public_key()))
    ]

    c.executemany("INSERT OR REPLACE INTO users VALUES (?, ?, ?, ?)", users)
    conn.commit()
    conn.close()
