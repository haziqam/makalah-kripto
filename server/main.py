from fastapi import FastAPI, HTTPException, UploadFile, Form, File
from pydantic import BaseModel
import base64 
from base64 import b64encode, b64decode

from proxy_server import (
    login as login_logic,
    get_public_key as get_keys_logic,
    upload_encrypted_file as upload_logic,
    grant_access as grant_logic,
    access_file as access_logic
)

app = FastAPI()

class LoginRequest(BaseModel):
    username: str
    password: str

class GrantRequest(BaseModel):
    file_name: str
    uploader_username: str
    receiver_username: str
    kfrag: str

class AccessRequest(BaseModel):
    file_name: str
    uploader_username: str
    receiver_username: str

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
            "encryption_pk": b64encode(bytes(encryption_pk)).decode(),
            "verifying_pk": b64encode(bytes(verifying_pk)).decode(),
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

    return {
        "file_name": file_name,
        "uploader": uploader_username,
        "capsule_size": len(capsule_bytes),
        "ciphertext_size": len(ciphertext_bytes)
    }


@app.post("/grant")
def grant_access(data: GrantRequest):
    try:
        kfrag_bytes = b64decode(data.kfrag)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 encoding: {str(e)}")

    result = grant_logic(
        file_name=data.file_name,
        uploader_username=data.uploader_username,
        receiver_username=data.receiver_username,
        kfrag_bytes=kfrag_bytes
    )

    if result:
        return {"success": True}
    raise HTTPException(status_code=404, detail="File or metadata not found")


@app.post("/access-file")
def access_file(data: AccessRequest):
    result = access_logic(
        file_name=data.file_name,
        uploader_username=data.uploader_username,
        receiver_username=data.receiver_username
    )

    if not result:
        raise HTTPException(status_code=403, detail="Access denied or file not found")

    ciphertext, capsule_bytes, cfrag_bytes = result

    return {
        "ciphertext": b64encode(ciphertext).decode(),
        "capsule": b64encode(capsule_bytes).decode(),
        "cfrag": b64encode(cfrag_bytes).decode()
    }
