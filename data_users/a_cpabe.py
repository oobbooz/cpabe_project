import os
import base64
import firebase_admin
from firebase_admin import credentials, firestore, auth
from charm.core.engine.util import bytesToObject
from CPABE import CPABE 
from Crypto.Cipher import AES
from firebase_admin import firestore, initialize_app
from charm.toolbox.pairinggroup import PairingGroup

cpabe = CPABE("AC17")
group = PairingGroup('SS512')
cpabe.groupObj = group


def decrypt(ciphertext: str, secret_key_path: str, public_key_path: str):
    try:
        with open(secret_key_path, "rb") as f:
            secret_key_bytes = f.read()
        with open(public_key_path, "rb") as f:
            public_key_bytes = f.read()

        secret_key = bytesToObject(secret_key_bytes, group)
        public_key = bytesToObject(public_key_bytes, group)

        decrypted_bytes = cpabe.AC17decrypt(public_key, ciphertext, secret_key)

        if decrypted_bytes is None:
            raise Exception("Decryption failed")

        try:
            return decrypted_bytes.decode("utf-8")
        except UnicodeDecodeError:
            print("[Notice] Data is an image or binary file.")
            return decrypted_bytes

    except Exception as e:
        print("Error:", e)
        return f"[Error] {str(e)}"
