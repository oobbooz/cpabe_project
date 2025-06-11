import os
import base64
import firebase_admin
from firebase_admin import credentials, firestore
from dotenv import load_dotenv
from charm.core.engine.util import bytesToObject
from CPABE import CPABE 

load_dotenv()

raw_path = os.getenv('SERVICE_ACCOUNT_PATH')
service_account_path = os.path.expanduser(raw_path)

if not firebase_admin._apps:
    cred = credentials.Certificate(service_account_path)
    firebase_admin.initialize_app(cred)

db = firestore.client()

cpabe = CPABE("AC17")

def encrypt(public_key_bytes: bytes, message_bytes: bytes, policy: str) -> str:
    public_key = bytesToObject(public_key_bytes, cpabe.groupObj)
    encrypted_str = cpabe.AC17encrypt(public_key, message_bytes, policy)
    return encrypted_str

def save_to_firestore(cipher_str: str, doc_name: str, owner: str, department: str, doc_type: str):
    doc_ref = db.collection("messages").document()  
    doc_data = {
        "ciphertext": cipher_str,
        "owner": owner,
        "department": department,
        "type": doc_type,
        "name": doc_name if doc_name else doc_ref.id  
    }

    doc_ref.set(doc_data)
    print(f"Document with ID {doc_ref.id} saved successfully.")

