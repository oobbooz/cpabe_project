import os
import base64
import firebase_admin
from firebase_admin import credentials, firestore,auth
from dotenv import load_dotenv
from charm.core.engine.util import bytesToObject
from CPABE import CPABE 
from Crypto.Cipher import AES
from firebase_admin import firestore, initialize_app
from charm.toolbox.pairinggroup import PairingGroup

load_dotenv()

raw_path = os.getenv('SERVICE_ACCOUNT_PATH')
service_account_path = os.path.expanduser(raw_path)

if not firebase_admin._apps:
    cred = credentials.Certificate(service_account_path)
    firebase_admin.initialize_app(cred)

db = firestore.client()

cpabe = CPABE("AC17")
group = PairingGroup('SS512')
cpabe.groupObj = group
def get_email_from_token(id_token):
    try:
        decoded_token = auth.verify_id_token(id_token)
        email = decoded_token.get('email')
        return email
    except Exception as e:
        print("Invalid token:", e)
        return None
def decrypt_document_local(document_id: str, secret_key_path: str, public_key_path: str):
    try:
        with open(secret_key_path, "rb") as f:
            secret_key_bytes = f.read()
        with open(public_key_path, "rb") as f:
            public_key_bytes = f.read()

        secret_key = bytesToObject(secret_key_bytes, group)
        public_key = bytesToObject(public_key_bytes, group)

        doc_ref = db.collection("messages").document(document_id)
        doc = doc_ref.get()
        if not doc.exists:
            raise Exception("Document not found")

        cipher_text = doc.to_dict().get("ciphertext")
        if not cipher_text:
            raise Exception("Ciphertext not found in document")
        print("Ciphertext (first 100 chars):", cipher_text[:100])

        decrypted_bytes = cpabe.AC17decrypt(public_key, cipher_text, secret_key)

        if decrypted_bytes is None:
            raise Exception("Decryption failed or invalid ciphertext")

        try:
            decrypted_text = decrypted_bytes.decode("utf-8")
            print("Decrypted Text:\n", decrypted_text)
            return decrypted_text
        except UnicodeDecodeError:
            print("[Thông báo] File được giải mã là ảnh hoặc dữ liệu nhị phân.")
            return None

    except Exception as e:
        print("Error:", e)
        return f"[Lỗi] {str(e)}"


def get_documents_by_type_and_department(doc_type: str, department: str = None):
    try:
        collection_ref = db.collection("messages")
        query = collection_ref.where("type", "==", doc_type)  

        if department:
            query = query.where("department", "==", department)

        docs = query.stream()
        result = []

        for doc in docs:
            data = doc.to_dict()
            result.append({
                "id": doc.id,
                "name": data.get("name"),                   
                "type": data.get("type"),                   
                "department": data.get("department"),
                "owner": data.get("owner"),
                "ciphertext": data.get("ciphertext")      
            })

        return result

    except Exception as e:
        print("Error fetching documents:", str(e))
        return []


