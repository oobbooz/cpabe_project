import os
import requests
import jwt
import json
import datetime
from dotenv import load_dotenv
load_dotenv()
FIREBASE_API_KEY = os.getenv("API_KEY")
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")
FIREBASE_SIGNIN_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
FIRESTORE_URL = f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/databases/(default)/documents/users"

with open("resource/ecdsa_private.pem", "r") as f:
    PRIVATE_KEY = f.read()

def handle_login_request(payload):
    try:
        email = payload.get("email")
        password = payload.get("password")

        if not email or not password:
            return {"status": "error", "message": "Missing email or password."}

        firebase_payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }

        res = requests.post(FIREBASE_SIGNIN_URL, json=firebase_payload)
        if res.status_code != 200:
            error_code = res.json().get("error", {}).get("message", "")
            return {"status": "error", "message": error_code}

        user_info = res.json()
        uid = user_info.get("localId")
        id_token = user_info.get("idToken")

        doc_url = f"{FIRESTORE_URL}/{uid}"
        headers = {
            "Authorization": f"Bearer {id_token}"
        }
        firestore_res = requests.get(doc_url, headers=headers)
        if firestore_res.status_code != 200:
            return {"status": "error", "message": "Cannot fetch user details from Firestore."}

        firestore_data = firestore_res.json()
        fields = firestore_data.get("fields", {})

        role = fields.get("role", {}).get("stringValue", "")
        department = fields.get("department", {}).get("stringValue", "")
        position = fields.get("position", {}).get("stringValue", "")
        location = fields.get("location", {}).get("stringValue", "")
        full_name = fields.get("fullName", {}).get("stringValue", "")

        claims = {
            "uid": uid,
            "email": email,
            "fullName": full_name,
            "role": role,
            "department": department,
            "position": position,
            "location": location,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }

        jwt_token = jwt.encode(claims, PRIVATE_KEY, algorithm="ES256")

        return {"status": "ok", "jwt": jwt_token}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}
