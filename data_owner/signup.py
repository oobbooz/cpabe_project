# signup.py

import tkinter as tk
from tkinter import ttk, messagebox
import requests, json, datetime, os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("API_KEY")
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")

SIGNUP_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={API_KEY}"
FIRESTORE_URL = f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/databases/(default)/documents/pending_users"

department_to_positions = {
    "IT": ["DEV", "TESTER"],
    "SALES": ["SALESREP", "ACCOUNTMANAGER"],
    "HR": ["HRMANAGER", "RECRUITER"],
    "FINANCE": ["ACCOUNTANT", "FINANCIALANALYST"]
}

class SignupWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Data Owner Account Sign Up")
        self.root.geometry("900x700")
        self.root.resizable(False, False)
        self.root.configure(bg="#e6f0ff")

        self.build_ui()

    def build_ui(self):
        style = ttk.Style(self.root)
        style.theme_use('clam')
        style.configure("TLabel", font=("Segoe UI", 13), background="#e6f0ff")
        style.configure("TEntry", font=("Segoe UI", 13))
        style.configure("TCombobox", font=("Segoe UI", 13))
        style.configure("TButton", font=("Segoe UI", 14, "bold"), padding=8)

        frame_basic = ttk.LabelFrame(self.root, text="Basic Information", padding=20)
        frame_basic.pack(fill="x", padx=30, pady=15)

        ttk.Label(frame_basic, text="Email:").grid(row=0, column=0, sticky="w", pady=10, padx=10)
        self.entry_email = ttk.Entry(frame_basic, width=40)
        self.entry_email.grid(row=0, column=1, pady=10, padx=10)

        ttk.Label(frame_basic, text="Password:").grid(row=1, column=0, sticky="w", pady=10, padx=10)
        self.entry_password = ttk.Entry(frame_basic, show="*", width=40)
        self.entry_password.grid(row=1, column=1, pady=10, padx=10)

        ttk.Label(frame_basic, text="Full Name:").grid(row=2, column=0, sticky="w", pady=10, padx=10)
        self.entry_fullname = ttk.Entry(frame_basic, width=40)
        self.entry_fullname.grid(row=2, column=1, pady=10, padx=10)

        ttk.Label(frame_basic, text="Role:").grid(row=3, column=0, sticky="w", pady=10, padx=10)
        self.combo_role = ttk.Combobox(frame_basic, values=["MANAGER", "EMPLOYEE"], state='readonly', width=37)
        self.combo_role.grid(row=3, column=1, pady=10, padx=10)

        frame_org = ttk.LabelFrame(self.root, text="Organization Information", padding=20)
        frame_org.pack(fill="x", padx=30, pady=15)

        ttk.Label(frame_org, text="Department:").grid(row=0, column=0, sticky="w", pady=10, padx=10)
        self.combo_department = ttk.Combobox(frame_org, values=list(department_to_positions.keys()), state='readonly', width=37)
        self.combo_department.grid(row=0, column=1, pady=10, padx=10)
        self.combo_department.bind("<<ComboboxSelected>>", self.on_department_change)

        ttk.Label(frame_org, text="Position:").grid(row=1, column=0, sticky="w", pady=10, padx=10)
        self.combo_position = ttk.Combobox(frame_org, state='disabled', width=37)
        self.combo_position.grid(row=1, column=1, pady=10, padx=10)

        ttk.Label(frame_org, text="Location:").grid(row=2, column=0, sticky="w", pady=10, padx=10)
        self.combo_location = ttk.Combobox(frame_org, values=["HCM", "HN"], state='readonly', width=37)
        self.combo_location.grid(row=2, column=1, pady=10, padx=10)

        ttk.Button(self.root, text="Sign Up", command=self.signup).pack(pady=20, ipadx=12, ipady=8)
        ttk.Button(self.root, text="Sign In", command=self.go_to_signin).pack(pady=5, ipadx=12, ipady=8)

    def on_department_change(self, event):
        dept = self.combo_department.get()
        positions = department_to_positions.get(dept, [])
        self.combo_position['values'] = positions
        if positions:
            self.combo_position.config(state='readonly')
            self.combo_position.set(positions[0])
        else:
            self.combo_position.config(state='disabled')
            self.combo_position.set('')

    def clear_form(self):
        self.entry_email.delete(0, tk.END)
        self.entry_password.delete(0, tk.END)
        self.entry_fullname.delete(0, tk.END)
        self.combo_role.set('')
        self.combo_department.set('')
        self.combo_position.set('')
        self.combo_position.config(state='disabled')
        self.combo_location.set('')

    def signup(self):
        email = self.entry_email.get().strip()
        password = self.entry_password.get().strip()
        full_name = self.entry_fullname.get().strip()
        role = self.combo_role.get()
        department = self.combo_department.get()
        position = self.combo_position.get()
        location = self.combo_location.get()

        if not email or not password or not full_name or not role:
            messagebox.showwarning("Warning", "Please fill in Email, Password, Full Name and Role.")
            return

        signup_payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        res = requests.post(SIGNUP_URL, data=json.dumps(signup_payload))
        if res.status_code != 200:
            error_message = res.json().get("error", {}).get("message", "Signup error")
            messagebox.showerror("Signup Error", error_message)
            return

        user_data = res.json()
        user_id = user_data.get("localId")
        id_token = user_data.get("idToken")

        now = datetime.datetime.utcnow().isoformat() + "Z"
        doc_data = {
            "fields": {
                "fullName": {"stringValue": full_name},
                "email": {"stringValue": email},
                "role": {"stringValue": role},
                "approved": {"booleanValue": False},
                "createdAt": {"timestampValue": now},
                "department": {"stringValue": department},
                "position": {"stringValue": position},
                "location": {"stringValue": location}
            }
        }

        url = f"{FIRESTORE_URL}/{user_id}"
        headers = {
            "Authorization": f"Bearer {id_token}",
            "Content-Type": "application/json"
        }
        firestore_res = requests.patch(url, data=json.dumps(doc_data), headers=headers)
        if firestore_res.status_code in (200, 201):
            messagebox.showinfo("Success", "Your account has been created and is pending admin approval.")
            self.clear_form()
        else:
            try:
                err = firestore_res.json()
            except Exception:
                err = firestore_res.text
            messagebox.showerror("Error", f"Cannot save user info to Firestore.\n{err}")

    def go_to_signin(self):
        self.root.destroy()
        from signin import LoginWindow
        LoginWindow().run()

    def run(self):
        self.root.mainloop()
if __name__ == "__main__":
    SignupWindow().run()
   
