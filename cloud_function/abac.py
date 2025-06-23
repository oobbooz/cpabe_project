import os
import logging
from werkzeug.exceptions import HTTPException
import firebase_admin
from firebase_admin import credentials, firestore

if not firebase_admin._apps:
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)

db = firestore.client()

class ABAC:
    def __init__(self):
        try:
            self.db = db  
        except Exception as e:
            logging.error(f"Error initializing Firestore: {e}")
            raise HTTPException(status_code=500, detail="Failed to connect to the policy database")

        self.policies = []
        self.load_policies()

    def load_policies(self):
        try:
            docs = self.db.collection("policies").stream()
            self.policies = [doc.to_dict() for doc in docs]
        except Exception as e:
            logging.error(f"Error loading policies: {e}")
            raise HTTPException(status_code=500, detail="Failed to load policies")

    def _resolve_condition_value(self, val, resource):
        if isinstance(val, str) and val.startswith("${resource.") and val.endswith("}"):
            key = val[len("${resource."):-1]
            resolved = resource.get(key)
            return resolved
        return val

    def _get_value_with_dollar(self, obj: dict, key: str):
        if key.startswith("$."):
            real_key = key[2:]
            return obj.get(real_key)
        else:
            return obj.get(key)

    def check_access(self, user_attrs, resource_attrs):
        for policy in self.policies:

            targets = policy.get("targets", {})
            target_type_cond = targets.get("type", {})

            resource_type = resource_attrs.get("type", "")
            if resource_type:
                resource_type = resource_type.upper()

            if "equals" in target_type_cond:
                if resource_type != target_type_cond["equals"].upper():
                    continue
            elif "in" in target_type_cond:
                in_values = [v.upper() for v in target_type_cond["in"]]
                if resource_type not in in_values:
                    continue

            subject = policy.get("subject", {})
            matched = True
            for key, cond in subject.items():
                user_key = key[2:] if key.startswith("$.") else key
                user_val = user_attrs.get(user_key, "")
                if user_val:
                    user_val = user_val.upper()

                cond_key = list(cond.keys())[0]
                cond_val = self._resolve_condition_value(cond[cond_key], resource_attrs)

                if isinstance(cond_val, list):
                    cond_val = [v.upper() for v in cond_val]
                else:
                    cond_val = cond_val.upper()

                if cond_key == "equals":
                    if isinstance(cond_val, list):
                        if not isinstance(user_val, list):
                            user_val = [user_val]
                        user_val_set = set(user_val)
                        cond_val_set = set(cond_val)
                        if user_val_set != cond_val_set:
                            matched = False
                            break
                    else:
                        if user_val != cond_val:
                            matched = False
                            break

            if matched:
                print("Policy matched")
                return policy.get("effect") == "allow"

        print("No matching allow policy found")
        return False
