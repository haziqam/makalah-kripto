# Simple PRE-based file sharing system

### Description

This experiment uses Proxy Re-encryption (PRE) to enable secure file sharing between users. In this system, a user (the data owner) can encrypt a file using their public key and upload it to a proxy server. Later, they can delegate access to a recipient by generating a re-encryption key fragment (kfrag), which the server uses to transform the encrypted file capsule into a cfrag — a capsule fragment re-encrypted for the recipient. The server never sees the plaintext and is not trusted with any private keys.

The client includes a simple REPL interface where users can log in, upload encrypted files, grant access to others, and access files shared with them. This setup demonstrates how PRE can be used for decentralized access control and secure data delegation without sharing private keys or the original plaintext.

### How to run:

1.  Install requirements

    ```
    pip install -r requirements.txt
    ```

2.  Set up sqlite database.

    ```
    cd server
    python db.py
    ```

    For this experiment, the database is prepopulated with these users (see db.py):

    ```
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
    ```

    You can use some prepared uses for experimenting; alice, bob, and carol, each with their own directory `/alice`, `/bob`, and `/carol`. Each of them has stored their private keys in their own directories with this format `encryption_sk.txt` and `signing_sk.txt`

3.  Run the server

    ```
    uvicorn main:app --reload
    ```

4.  On a separate terminal, run the client, you can run multiple clients from multiple terminals

    ```
    cd client
    python main.py
    ```
