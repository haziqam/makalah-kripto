import sqlite3
from pathlib import Path
from umbral import Capsule, PublicKey, VerifiedKeyFrag, reencrypt
from db import DB_PATH


DATA_DIR = Path("server_data/files")
DATA_DIR.mkdir(parents=True, exist_ok=True)


def login(username: str, password: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        return c.fetchone() is not None

def get_public_key(username: str) -> tuple[PublicKey, PublicKey]:
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT encryption_pk, verifying_pk FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if row:
            encryption_pk = PublicKey.from_bytes(row[0])
            verifying_pk = PublicKey.from_bytes(row[1])
            return encryption_pk, verifying_pk
        return None, None

def upload_encrypted_file(file_name: str, uploader_username: str, capsule_bytes: bytes, ciphertext_bytes: bytes) -> bool:
    file_path = DATA_DIR / f"{uploader_username}__{file_name}"
    file_path.write_bytes(ciphertext_bytes)

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # store capsule as hex string
        c.execute('''INSERT OR REPLACE INTO files (file_name, uploader, capsule, ciphertext_path)
                     VALUES (?, ?, ?, ?)''',
                  (file_name, uploader_username, capsule_bytes.hex(), str(file_path)))
        conn.commit()
        return True

def grant_access(file_name: str, uploader_username: str, receiver_username: str, kfrag_bytes: bytes) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()

        c.execute("SELECT id, capsule FROM files WHERE file_name=? AND uploader=?", (file_name, uploader_username))
        file_row = c.fetchone()

        if not file_row:
            print("File not found")
            return False
        
        file_id, capsule_bytes = file_row
        capsule = Capsule.from_bytes(bytes.fromhex(capsule_bytes))


        kfrag = VerifiedKeyFrag.from_verified_bytes(kfrag_bytes)
        cfrag = reencrypt(capsule=capsule, kfrag=kfrag)

        c.execute('''INSERT OR REPLACE INTO file_permission (file_id, receiver, cfrag)
                     VALUES (?, ?, ?)''',
                  (file_id, receiver_username, bytes(cfrag)))
        conn.commit()
        return True

    
def access_file(file_name: str, uploader_username: str, receiver_username: str) -> tuple[bytes, bytes, bytes] | None:
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id, capsule, ciphertext_path FROM files WHERE file_name=? AND uploader=?",
                  (file_name, uploader_username))
        file_row = c.fetchone()
        
        if not file_row:
            print("File not found.")
            return None

        file_id, capsule_hex, ciphertext_path = file_row
        capsule_bytes = bytes.fromhex(capsule_hex)

        ciphertext = Path(ciphertext_path).read_bytes()

        c.execute("SELECT cfrag FROM file_permission WHERE file_id=? AND receiver=?", (file_id, receiver_username))
        file_permission_row = c.fetchone()

        if not file_permission_row:
            print("No permission")
            return None
        
        cfrag_bytes = file_permission_row[0]

        return ciphertext, capsule_bytes, cfrag_bytes
