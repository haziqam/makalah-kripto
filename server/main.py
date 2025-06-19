from fastapi import FastAPI, HTTPException, UploadFile, Form, File
from pydantic import BaseModel
from typing import Optional
from umbral import PublicKey
import base64


from proxy_server import (
    login as login_logic,
    get_public_key as get_keys_logic,
    register_websocket,
    unregister_websocket,
    upload_encrypted_file as upload_logic,
    grant_access as grant_logic
)

app = FastAPI()


class LoginRequest(BaseModel):
    username: str
    password: str

class UploadRequest(BaseModel):
    file_name: str
    uploader_username: str
    capsule: bytes
    ciphertext: bytes

class GrantRequest(BaseModel):
    file_name: str
    uploader_username: str
    receiver_username: str
    kfrag: bytes


# === Endpoints ===

@app.post("/login")
def login(data: LoginRequest):
    if login_logic(data.username, data.password):
        return {"success": True}
    return {"success": False}


@app.get("/keys/{username}")
def get_keys(username: str):
    encryption_pk, verifying_pk = get_keys_logic(username)
    if encryption_pk and verifying_pk:
        return {
            "encryption_pk": base64.b64encode(bytes(encryption_pk)).decode(),
            "verifying_pk": base64.b64encode(bytes(verifying_pk)).decode(),
        }
    raise HTTPException(status_code=404, detail="User not found")



@app.post("/upload")
async def upload_file(
    file_name: str = Form(...),
    uploader_username: str = Form(...),
    capsule: UploadFile = File(...),
    ciphertext: UploadFile = File(...)
):
    capsule_bytes = await capsule.read()
    ciphertext_bytes = await ciphertext.read()

    upload_logic(file_name, uploader_username, capsule_bytes, ciphertext_bytes)

    # process your files
    return {
        "file_name": file_name,
        "uploader": uploader_username,
        "capsule_size": len(capsule_bytes),
        "ciphertext_size": len(ciphertext_bytes)
    }

@app.post("/grant")
def grant_access(data: GrantRequest):
    result = grant_logic(
        file_name=data.file_name,
        uploader_username=data.uploader_username,
        receiver_username=data.receiver_username,
        kfrag_bytes=data.kfrag
    )

    if result:
        kfrag, capsule, ciphertext = result
        return {
            "kfrag": kfrag,
            "capsule": capsule,
            "ciphertext": ciphertext
        }
    return {"error": "File or metadata not found"}, 404

from fastapi import WebSocket, WebSocketDisconnect

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    await websocket.accept()
    register_websocket(username, websocket)
    try:
        while True:
            await websocket.receive_text()  # Keeps connection alive
    except WebSocketDisconnect:
        unregister_websocket(username)

