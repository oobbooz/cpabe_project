import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import jwt
from a_cpabe import encrypt, save_to_firestore
from connect import Client  
import threading

class UploadApp:
    def __init__(self, master, id_token):
        self.positions_map = {
            "IT": ["DEV", "TESTER"],
            "SALES": ["SALESREP", "ACCOUNTMANAGER"],
            "HR": ["RECRUITER", "HRMANAGER"],
            "FINANCE": ["ACCOUNTANT", "FINANCIALANALYST"]
        }

        self.master = master
        self.master.title(" Gửi tài liệu")
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
                "fullName": decoded.get("email", "Không rõ tên"),
                "department": decoded.get("department", "Không rõ phòng ban")
            }
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể giải mã token: {e}")
            return {"fullName": "Không rõ tên", "department": "Không rõ phòng ban"}

    def create_widgets(self):
        self.master.geometry("900x900") 

        pad = {'padx': 12, 'pady': 10}  
        row = 0

        user_frame = tk.Frame(self.master, relief=tk.RIDGE, borderwidth=1)
        user_frame.grid(row=row, column=0, columnspan=3, sticky='ew', padx=15, pady=15)
        row += 1
        btn_frame = tk.Frame(self.master)
        btn_frame.grid(row=row, column=0, columnspan=3)
        row += 1

        btn_get_pk = tk.Button(btn_frame, text="Lấy Khóa Public Key", command=self.thread_get_public_key)
        btn_get_pk.pack()

        doc_frame = tk.Frame(self.master, relief=tk.RIDGE, borderwidth=1)
        doc_frame.grid(row=row, column=0, columnspan=3, sticky='ew', padx=15, pady=15)
        row += 1

        tk.Label(doc_frame, text="Chọn Public Key:", font=("Arial", 12)).grid(row=0, column=0, sticky='w', **pad)


        tk.Label(user_frame, text="Họ tên:", font=("Arial", 12)).grid(row=0, column=0, sticky='w', **pad)
        tk.Label(user_frame, text=self.user_info["fullName"], font=("Arial", 12, 'bold')).grid(row=0, column=1, sticky='w', **pad)
        tk.Label(user_frame, text="Phòng ban:", font=("Arial", 12)).grid(row=1, column=0, sticky='w', **pad)
        tk.Label(user_frame, text=self.user_info["department"], font=("Arial", 12, 'bold')).grid(row=1, column=1, sticky='w', **pad)
        btn_frame = tk.Frame(self.master)
        btn_frame.grid(row=row, column=0, sticky='w', padx=15, pady=10)

        btn_get_pk = tk.Button(btn_frame, text="Lấy Khóa Public Key", command=self.thread_get_public_key)
        btn_get_pk.pack()
        doc_frame = tk.Frame(self.master, relief=tk.RIDGE, borderwidth=1)
        doc_frame.grid(row=row, column=0, columnspan=3, sticky='ew', padx=15, pady=15)
        row += 1

        tk.Label(doc_frame, text="Chọn Public Key:", font=("Arial", 12)).grid(row=0, column=0, sticky='w', **pad)
        tk.Button(doc_frame, text="Chọn...", width=15, height=1, font=("Arial", 11), command=self.select_pubkey).grid(row=0, column=1, **pad)
        tk.Label(doc_frame, textvariable=self.pubkey_path, font=("Arial", 11), wraplength=400).grid(row=0, column=2, sticky='w')

        tk.Label(doc_frame, text="Chọn File:", font=("Arial", 12)).grid(row=1, column=0, sticky='w', **pad)
        tk.Button(doc_frame, text="Chọn...", width=15, height=1, font=("Arial", 11), command=self.select_file).grid(row=1, column=1, **pad)
        tk.Label(doc_frame, textvariable=self.file_path, font=("Arial", 11), wraplength=400).grid(row=1, column=2, sticky='w')

        tk.Label(doc_frame, text="Tên tài liệu:", font=("Arial", 12)).grid(row=2, column=0, sticky='w', **pad)
        self.entry_name = tk.Entry(doc_frame, width=40, font=("Arial", 12))
        self.entry_name.grid(row=2, column=1, columnspan=2, sticky='w', **pad)

        tk.Label(doc_frame, text="Loại tài liệu:", font=("Arial", 12)).grid(row=3, column=0, sticky='w', **pad)
        self.doc_type = ttk.Combobox(doc_frame, values=["internal", "external"], state='readonly', font=("Arial", 12), width=20)
        self.doc_type.grid(row=3, column=1, columnspan=2, sticky='w', **pad)
        self.doc_type.bind("<<ComboboxSelected>>", self.on_type_change)

        policy_frame = tk.Frame(self.master, relief=tk.RIDGE, borderwidth=1)
        policy_frame.grid(row=row, column=0, columnspan=3, sticky='ew', padx=15, pady=15)
        row += 1

        tk.Label(policy_frame, text="Department", font=("Arial", 12)).grid(row=0, column=0, sticky='w', **pad)
        self.dept_frame = tk.Frame(policy_frame)
        self.dept_frame.grid(row=0, column=1, columnspan=2, sticky='w', **pad)
        self.groups["department"] = []
        for dept in self.positions_map.keys():
            var = tk.BooleanVar()
            cb = tk.Checkbutton(self.dept_frame, text=dept, variable=var, font=("Arial", 11), command=self.on_department_change)
            cb.pack(side='left', padx=8, pady=5)
            self.groups["department"].append((dept, var))

        tk.Label(policy_frame, text="Position", font=("Arial", 12)).grid(row=1, column=0, sticky='w', **pad)
        self.position_frame = tk.Frame(policy_frame)
        self.position_frame.grid(row=1, column=1, columnspan=2, sticky='w', **pad)
        self.groups["position"] = []
        self.position_vars = {}

        tk.Label(policy_frame, text="Location", font=("Arial", 12)).grid(row=2, column=0, sticky='w', **pad)
        location_frame = tk.Frame(policy_frame)
        location_frame.grid(row=2, column=1, columnspan=2, sticky='w', **pad)
        locs = ["HCM", "HN"]
        self.groups["location"] = []
        for loc in locs:
            var = tk.BooleanVar()
            cb = tk.Checkbutton(location_frame, text=loc, variable=var, font=("Arial", 11), command=self.build_policy)
            cb.pack(side='left', padx=8, pady=5)
            self.groups["location"].append((loc, var))

        tk.Label(policy_frame, text="Role", font=("Arial", 12)).grid(row=3, column=0, sticky='w', **pad)
        role_frame = tk.Frame(policy_frame)
        role_frame.grid(row=3, column=1, columnspan=2, sticky='w', **pad)
        roles = ["MANAGER", "EMPLOYEE"]
        self.groups["role"] = []
        for role in roles:
            var = tk.BooleanVar()
            cb = tk.Checkbutton(role_frame, text=role, variable=var, font=("Arial", 11), command=self.build_policy)
            cb.pack(side='left', padx=8, pady=5)
            self.groups["role"].append((role, var))

        tk.Label(self.master, text="Policy:", font=("Arial", 12)).grid(row=row, column=0, sticky='w', **pad)
        tk.Entry(self.master, textvariable=self.policy_var, width=60, font=("Arial", 12), state='readonly').grid(row=row, column=1, columnspan=2, sticky='w', **pad)

        row += 1
        tk.Button(self.master, text="📨 Gửi tài liệu", font=("Arial", 13, "bold"), width=30, height=2, command=self.send).grid(row=row, column=0, columnspan=3, pady=20)
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
        positions = list(dict.fromkeys(positions))  # loại trùng

        for pos in positions:
            var = tk.BooleanVar()
            cb = tk.Checkbutton(self.position_frame, text=pos, variable=var, command=self.build_policy)
            cb.pack(side='left')
            self.groups["position"].append((pos, var))
            self.position_vars[pos] = var

        self.build_policy()



    def select_pubkey(self):
        path = filedialog.askopenfilename(title="Chọn public key file")
        if path:
            self.pubkey_path.set(path)

    def select_file(self):
        path = filedialog.askopenfilename(title="Chọn file tài liệu")
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
            save_path = os.getcwd()  
            if not os.path.exists(save_path):
                os.makedirs(save_path)
            file_name = 'public_key.bin'
            client.connect_to_server(mode='get_pub_key', save_path=save_path, file_name=file_name)
            print("Saving public key to:", os.path.join(save_path, file_name))
            self.master.after(0, lambda: messagebox.showinfo("Thành công", f"Public key đã được lưu tại {os.path.join(save_path, file_name)}"))
        except Exception as e:
            self.master.after(0, lambda err=e: messagebox.showerror("Lỗi", f"Lấy khóa thất bại: {err}"))

    def send(self):
        try:
            with open(self.pubkey_path.get(), "rb") as f:
                pubkey = f.read()
            with open(self.file_path.get(), "rb") as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi đọc file: {e}")
            return

        policy = self.policy_var.get()
        if not policy:
            messagebox.showwarning("Thiếu policy", "Vui lòng chọn ít nhất một điều kiện.")
            return

        try:
            cipher = encrypt(pubkey, data, policy)
            save_to_firestore(
                cipher,
                self.entry_name.get() or "unnamed",
                self.user_info["fullName"],
                self.user_info["department"],
                self.doc_type.get() or "unknown",
               
            )
            
            messagebox.showinfo("✅ Thành công", "Tài liệu đã được gửi!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Gửi thất bại: {e}")

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
        print("Vui lòng cung cấp token hợp lệ.")
        sys.exit(1)

    run_upload_app(token)