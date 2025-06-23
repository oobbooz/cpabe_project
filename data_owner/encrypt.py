import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import jwt
from a_cpabe import encrypt, save_to_firestore_via_function
from connect import Client  
import threading
import json

class UploadApp:
    def __init__(self, master, id_token):
        self.positions_map = {
            "IT": ["DEV", "TESTER"],
            "SALES": ["SALESREP", "ACCOUNTMANAGER"],
            "HR": ["RECRUITER", "HRMANAGER"],
            "FINANCE": ["ACCOUNTANT", "FINANCIALANALYST"]
        }

        self.master = master
        self.master.title("Upload Document")
        self.id_token = id_token or ""
        self.user_info = self.decode_token()

        self.pubkey_path = tk.StringVar()
        self.file_path = tk.StringVar()
        self.policy_var = tk.StringVar()
        self.groups = {}

        self.create_widgets()

    def decode_token(self):
        try:
            decoded = jwt.decode(self.id_token, options={"verify_signature": False})
            return {
                "fullName": decoded.get("email", "Unknown"),
                "department": decoded.get("department", "Unknown")
            }
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decode token: {e}")
            return {"fullName": "Unknown", "department": "Unknown"}

    def create_widgets(self):
        self.master.geometry("800x800")
        self.master.configure(bg="#f0f4ff")
        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_columnconfigure(1, weight=1)
        self.master.grid_columnconfigure(2, weight=1)

        style = ttk.Style()
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"), foreground="#003366", backgroud="cceeff")

        title_frame = tk.Frame(self.master, bg="#cceeff", height=60,width=720)
        title_frame.grid(row=0, column=0, columnspan=3, sticky="ew")

        title_label = ttk.Label(
            title_frame,
            text="UPLOAD DOCUMENTS",
            style="Title.TLabel",
            anchor="center"
        )
        title_label.pack(expand=True, fill="both")

        pad = {'padx': 12, 'pady': 10}
        row = 1

        user_frame = tk.Frame(self.master, relief=tk.RIDGE, borderwidth=1, bg="#f0f4ff")
        user_frame.grid(row=row, column=0, columnspan=3, sticky='ew', padx=15, pady=15)
        row += 1

        tk.Label(user_frame, text="Email:", font=("Arial", 12), bg="#f0f4ff").grid(row=0, column=0, sticky='w', **pad)
        tk.Label(user_frame, text=self.user_info["fullName"], font=("Arial", 12, 'bold'), bg="#f0f4ff").grid(row=0, column=1, sticky='w', **pad)
        tk.Label(user_frame, text="Department:", font=("Arial", 12), bg="#f0f4ff").grid(row=1, column=0, sticky='w', **pad)
        tk.Label(user_frame, text=self.user_info["department"], font=("Arial", 12, 'bold'), bg="#f0f4ff").grid(row=1, column=1, sticky='w', **pad)

        btn_frame = tk.Frame(self.master, bg="#f0f4ff")
        btn_frame.grid(row=row, column=0, columnspan=3)
        row += 1
        btn_get_pk = tk.Button(btn_frame, text="Get Public Key", font=("Arial", 11), command=self.thread_get_public_key)
        btn_get_pk.pack(pady=(0, 10))

        doc_frame = tk.Frame(self.master, relief=tk.RIDGE, borderwidth=1, bg="#f0f4ff",width=720)
        doc_frame.grid(row=row, column=0, columnspan=3, sticky='ew', padx=15, pady=15)
        row += 1

        tk.Label(doc_frame, text="Public Key:", font=("Arial", 12), bg="#f0f4ff").grid(row=0, column=0, sticky='w', **pad)
        tk.Button(doc_frame, text="Browse...", width=15, font=("Arial", 11), command=self.select_pubkey).grid(row=0, column=1, **pad)
        tk.Label(doc_frame, textvariable=self.pubkey_path, font=("Arial", 11), wraplength=500, bg="#f0f4ff").grid(row=0, column=2, sticky='w')

        tk.Label(doc_frame, text="Document File:", font=("Arial", 12), bg="#f0f4ff").grid(row=1, column=0, sticky='w', **pad)
        tk.Button(doc_frame, text="Browse...", width=15, font=("Arial", 11), command=self.select_file).grid(row=1, column=1, **pad)
        tk.Label(doc_frame, textvariable=self.file_path, font=("Arial", 11), wraplength=500, bg="#f0f4ff").grid(row=1, column=2, sticky='w')

        tk.Label(doc_frame, text="Document Name:", font=("Arial", 12), bg="#f0f4ff").grid(row=2, column=0, sticky='w', **pad)
        self.entry_name = tk.Entry(doc_frame, width=40, font=("Arial", 12))
        self.entry_name.grid(row=2, column=1, columnspan=2, sticky='w', **pad)

        tk.Label(doc_frame, text="Document Type:", font=("Arial", 12), bg="#f0f4ff").grid(row=3, column=0, sticky='w', **pad)
        self.doc_type = ttk.Combobox(doc_frame, values=["internal", "external"], state='readonly', font=("Arial", 12), width=20)
        self.doc_type.grid(row=3, column=1, columnspan=2, sticky='w', **pad)
        self.doc_type.bind("<<ComboboxSelected>>", self.on_type_change)

        policy_frame = tk.Frame(self.master, relief=tk.RIDGE, borderwidth=1, bg="#f0f4ff",width=720)
        policy_frame.grid(row=row, column=0, columnspan=3, sticky='ew', padx=15, pady=15)
        row += 1

        tk.Label(policy_frame, text="Department", font=("Arial", 12), bg="#f0f4ff").grid(row=0, column=0, sticky='w', **pad)
        self.dept_frame = tk.Frame(policy_frame, bg="#f0f4ff")
        self.dept_frame.grid(row=0, column=1, columnspan=2, sticky='w', **pad)
        self.groups["department"] = []
        for dept in self.positions_map.keys():
            var = tk.BooleanVar()
            cb = tk.Checkbutton(self.dept_frame, text=dept, variable=var, font=("Arial", 11), bg="#f0f4ff", command=self.on_department_change)
            cb.pack(side='left', padx=8, pady=5)
            self.groups["department"].append((dept, var))

        tk.Label(policy_frame, text="Position", font=("Arial", 12), bg="#f0f4ff").grid(row=1, column=0, sticky='w', **pad)
        self.position_frame = tk.Frame(policy_frame, bg="#f0f4ff")
        self.position_frame.grid(row=1, column=1, columnspan=2, sticky='w', **pad)
        self.groups["position"] = []
        self.position_vars = {}

        tk.Label(policy_frame, text="Location", font=("Arial", 12), bg="#f0f4ff").grid(row=2, column=0, sticky='w', **pad)
        location_frame = tk.Frame(policy_frame, bg="#f0f4ff")
        location_frame.grid(row=2, column=1, columnspan=2, sticky='w', **pad)
        locs = ["HCM", "HN"]
        self.groups["location"] = []
        for loc in locs:
            var = tk.BooleanVar()
            cb = tk.Checkbutton(location_frame, text=loc, variable=var, font=("Arial", 11), bg="#f0f4ff", command=self.build_policy)
            cb.pack(side='left', padx=8, pady=5)
            self.groups["location"].append((loc, var))

        tk.Label(policy_frame, text="Role", font=("Arial", 12), bg="#f0f4ff").grid(row=3, column=0, sticky='w', **pad)
        role_frame = tk.Frame(policy_frame, bg="#f0f4ff")
        role_frame.grid(row=3, column=1, columnspan=2, sticky='w', **pad)
        roles = ["MANAGER", "EMPLOYEE"]
        self.groups["role"] = []
        for role in roles:
            var = tk.BooleanVar()
            cb = tk.Checkbutton(role_frame, text=role, variable=var, font=("Arial", 11), bg="#f0f4ff", command=self.build_policy)
            cb.pack(side='left', padx=8, pady=5)
            self.groups["role"].append((role, var))

        tk.Label(self.master, text="Policy:", font=("Arial", 12), bg="#f0f4ff").grid(row=row, column=0, sticky='w', **pad)
        tk.Entry(self.master, textvariable=self.policy_var, width=60, font=("Arial", 12), state='readonly').grid(row=row, column=1, columnspan=2, sticky='w', **pad)
        row += 1

        tk.Button(
            self.master,
            text="Upload Document",
            font=("Arial", 13, "bold"),
            width=30,
            height=2,
            bg="#0066cc",
            fg="white",
            command=self.send
        ).grid(row=row, column=0, columnspan=3, pady=20)


    def thread_get_public_key(self):
        t = threading.Thread(target=self.get_public_key)
        t.start()

    def on_department_change(self):
        for widget in self.position_frame.winfo_children():
            widget.destroy()
        self.groups["position"].clear()
        self.position_vars.clear()

        selected_depts = [dept for dept, var in self.groups["department"] if var.get()]
        positions = []
        for d in selected_depts:
            positions.extend(self.positions_map.get(d, []))
        positions = list(dict.fromkeys(positions))  

        for pos in positions:
            var = tk.BooleanVar()
            cb = tk.Checkbutton(self.position_frame, text=pos, variable=var, command=self.build_policy)
            cb.pack(side='left')
            self.groups["position"].append((pos, var))
            self.position_vars[pos] = var

        self.build_policy()

    def select_pubkey(self):
        path = filedialog.askopenfilename(title="Select public key file")
        if path:
            self.pubkey_path.set(path)

    def select_file(self):
        path = filedialog.askopenfilename(title="Select document file")
        if path:
            self.file_path.set(path)

    def build_policy(self):
        clauses = []
        for group, vars_list in self.groups.items():
            selected = [opt for opt, var in vars_list if var.get()]
            if selected:
                clauses.append(f"({' or '.join(selected)})")
        self.policy_var.set(" and ".join(clauses))

    def on_type_change(self, event):
        pass

    def get_public_key(self):
        try:
            client = Client(host='127.0.0.1', port=10023)
            save_path = os.path.join(os.getcwd(), "resource")
            if not os.path.exists(save_path):
                os.makedirs(save_path)
            file_name = 'public_key.bin'
            client.connect_to_server(mode='get_pub_key', save_path=save_path, file_name=file_name)
            self.master.after(0, lambda: messagebox.showinfo("Success", f"Public key saved to {os.path.join(save_path, file_name)}"))
        except Exception as e:
            self.master.after(0, lambda err=e: messagebox.showerror("Error", f"Failed to get public key: {err}"))

    def send(self):
        try:
            with open(self.pubkey_path.get(), "rb") as f:
                pubkey = f.read()
            with open(self.file_path.get(), "rb") as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"File read error: {e}")
            return

        policy = self.policy_var.get()
        if not policy:
            messagebox.showwarning("Missing Policy", "Please select at least one condition.")
            return

        departments_selected = [dept for dept, var in self.groups["department"] if var.get()]
        if not departments_selected:
            messagebox.showwarning("Missing Department", "Please select at least one department.")
            return

        try:
            cipher = encrypt(pubkey, data, policy)

            document = {
                "ciphertext": cipher,
                "department": departments_selected,
                "name": self.entry_name.get() or "unnamed",
                "owner": self.user_info["fullName"],
                "type": self.doc_type.get() or "unknown"
            }

            resource = {
                "type": document["type"],
                "department": departments_selected
            }

            response = save_to_firestore_via_function(
                token=self.id_token,
                resource=resource,
                document=document
            )
            try:
                res_json = response.json()
            except Exception:
                res_json = {}

            if response.status_code == 200:
                messagebox.showinfo("Success", "Document uploaded successfully.")
            elif response.status_code == 403:
                messagebox.showwarning("Permission Denied", res_json.get("detail", "Access denied."))
            elif response.status_code == 400:
                messagebox.showerror("Invalid Request", res_json.get("detail", "Bad request."))
            else:
                messagebox.showerror("Error", f"Upload failed. Server returned: {response.status_code}\n{res_json.get('detail', '')}")


        except Exception as e:
            messagebox.showerror("Error", f"Upload failed: {e}")


def run_upload_app(id_token):
    root = tk.Tk()
    app = UploadApp(root, id_token)
    root.mainloop()

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        token = sys.argv[1]
    else:
        token = ""

    if not token or token == "...":
        print("Please provide a valid token.")
        sys.exit(1)

    run_upload_app(token)
