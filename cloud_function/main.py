import json
import jwt
from flask import Request, make_response
from abac import ABAC
from firebase_admin import auth

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECMKeCx+WV1pH2DnMGj3ql8QGiRCW
3QGC2uKJ6YKzEbwpij5ciCYUHV7gEtw3ZMYCYcIF6FOL5jJzIijsZL5FSQ==
-----END PUBLIC KEY-----"""

abac = ABAC()

def handle_request(request: Request):
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return make_response(json.dumps({"detail": "Unauthorized"}), 401)

    token = auth_header.split(" ")[1]

    try:
        decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["ES256"])
    except jwt.ExpiredSignatureError:
        return make_response(json.dumps({"detail": "Token expired"}), 401)
    except jwt.InvalidTokenError as e:
        return make_response(json.dumps({"detail": f"Invalid token: {str(e)}"}), 401)

    body = request.get_json(silent=True) or {}
    resource = body.get("resource", {})
    data = body.get("data", {})
    action = body.get("action", "read").lower()
    doc_id = resource.get("doc_id")

    if action == "create":
        if decoded.get("role", "").upper() != "ADMIN":
            return make_response(json.dumps({"detail": "Only admin can create employees"}), 403)

        try:
            employees = body.get("employees", [])
            if not isinstance(employees, list):
                return make_response(json.dumps({"detail": "Invalid employees data"}), 400)

            created_count = 0
            for user in employees:
                email = user.get("email", "").strip()
                password = user.get("password", "").strip()

                if not email or not password:
                    continue  

                user_record = auth.create_user(
                    email=email,
                    password=password,
                    display_name=user.get("fullName", "")
                )

                user_data = user.copy()
                user_data.pop("password", None)
                user_data["uid"] = user_record.uid  

                abac.db.collection("users").document(user_record.uid).set(user_data)
                created_count += 1

            return make_response(json.dumps({
                "status": "success",
                "message": f"{created_count} users created."
            }), 200)

        except Exception as e:
            return make_response(json.dumps({"detail": f"Failed to create users: {str(e)}"}), 500)
            
    if action == "write":
        if not resource or not data:
            return make_response(json.dumps({"detail": "Missing resource or data"}), 400)

        if abac.check_access(decoded, resource):
            try:
                doc_type = data.get("type", resource.get("type", "")).lower()

                payload = {
                    "ciphertext": data.get("ciphertext", ""),
                    "doc_name": data.get("name", ""),
                    "owner": data.get("owner", decoded.get("uid")),
                    "type": doc_type
                }

                if doc_type != "external":
                    department_value = data.get("department", resource.get("department", ""))
                    if isinstance(department_value, str):
                        department_value = [department_value]
                    payload["department"] = department_value

                abac.db.collection("documents").add(payload)
                print("Write succeeded")
                return make_response(json.dumps({"status": "success"}), 200)
            except Exception as e:
                print("Write error:", e)
                return make_response(json.dumps({"detail": f"Write failed: {str(e)}"}), 500)
        else:
            return make_response(json.dumps({"detail": "Permission denied"}), 403)


    elif action == "read":
        doc_id = resource.get("doc_id")
        docs_ref = abac.db.collection("documents")

        try:
            if isinstance(doc_id, str) and doc_id.strip():
                doc = docs_ref.document(doc_id).get()
                if not doc.exists:
                    return make_response(json.dumps({"detail": "Document not found"}), 404)

                doc_data = doc.to_dict()
                doc_type = doc_data.get("type", "").lower()
                resource["type"] = doc_type  

                if doc_type == "internal":
                    doc_depts = doc_data.get("department", [])
                    if isinstance(doc_depts, str):
                        doc_depts = [doc_depts]
                    resource["department"] = doc_depts
                else:
                    removed = resource.pop("department", None)

                if not abac.check_access(decoded, resource):
                    return make_response(json.dumps({"detail": "Permission denied"}), 403)

                if doc_type == "internal":
                    user_depts = decoded.get("department", [])
                    if isinstance(user_depts, str):
                        user_depts = [user_depts]
                    if not set(user_depts) & set(doc_depts):
                        return make_response(json.dumps({"detail": "Not authorized to access this department"}), 403)

                return make_response(json.dumps({
                    "doc_id": doc.id,
                    "ciphertext": doc_data.get("ciphertext", "")
                }), 200)

            else:
                if not resource.get("type"):
                    return make_response(json.dumps({"detail": "Missing resource type"}), 400)

                resource["type"] = resource["type"].lower()

                if resource["type"] == "external":
                    removed = resource.pop("department", None)

                if not abac.check_access(decoded, resource):
                    return make_response(json.dumps({"detail": "Permission denied"}), 403)

                query = docs_ref.where("type", "==", resource["type"])

                if resource["type"] == "internal":
                    departments = decoded.get("department", [])
                    if isinstance(departments, str):
                        departments = [departments]
                    if departments:
                        query = query.where("department", "array_contains_any", departments)

                docs = list(query.stream())

                results = []
                for doc in docs:
                    info = doc.to_dict()
                    results.append({
                        "doc_id": doc.id,
                        "doc_name": info.get("doc_name", "No name")
                    })

                return make_response(json.dumps(results), 200)

        except Exception as e:
            print("Query error:", e)
            return make_response(json.dumps({"detail": f"Read failed: {str(e)}"}), 500)



    else:
        return make_response(json.dumps({"detail": "Invalid action"}), 400)
