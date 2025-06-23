import os
import base64
from charm.core.engine.util import bytesToObject
from CPABE import CPABE 
import requests
import json 
from requests.models import Response

cpabe = CPABE("AC17")
def encrypt(public_key_bytes: bytes, message_bytes: bytes, policy: str) -> str:
    public_key = bytesToObject(public_key_bytes, cpabe.groupObj)
    encrypted_str = cpabe.AC17encrypt(public_key, message_bytes, policy)
    return encrypted_str

def save_to_firestore_via_function(token: str, resource: dict, document: dict) -> Response:
    function_url = "https://handle-request-itz4xkhbza-as.a.run.app"

    payload = {
        "action": "write",
        "resource": resource,
        "data": document
    }
    headers = {
        "Authorization": f"Bearer {token.strip()}",
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(function_url, headers=headers, data=json.dumps(payload))
        print("Response:", response.text)
        return response  

    except Exception as e:
        print("Failed to connect to Cloud Function:", str(e))
        fake_response = Response()
        fake_response.status_code = 500
        fake_response._content = json.dumps({"detail": str(e)}).encode("utf-8")
        return fake_response