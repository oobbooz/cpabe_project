
# class UploadApp:
#     def __init__(self, master, id_token):
#         self.positions_map = {
#         "IT": ["DEV", "TESTER"],
#         "SALES": ["SALESREP", "SALESEXECUTIVE"],
#         "HR": ["RECRUITER", "HREXECUTIVE"],
#         "FINANCE": ["FINALCIALANALYST", "TREASURER"]
#     }
#         self.master = master
#         self.master.title("📤 Gửi tài liệu")
#         self.master.geometry("750x700")
#         self.master.configure(bg="#f9f9f9")

#         self.id_token = id_token or ""
#         self.user_info = self.decode_token()

#         self.pubkey_path = tk.StringVar()
#         self.file_path = tk.StringVar()
#         self.policy_var = tk.StringVar()

#         # Department hiện tại của người dùng (hiển thị, không thay đổi)
#         self.current_department = self.user_info["department"]

#         # Policy selection
#         self.policy_departments = []  # departments selected for policy (external)
#         self.position_var = tk.StringVar()

#         self.doc_type_var = tk.StringVar()

#         self.create_widgets()

#     def decode_token(self):
#         try:
#             decoded = jwt.decode(self.id_token, options={"verify_signature": False})
#             return {
#                 "fullName": decoded.get("email", "Không rõ tên"),
#                 "department": decoded.get("department", "Không rõ phòng ban")
#             }
#         except Exception as e:
#             messagebox.showerror("Lỗi", f"Không thể giải mã token: {e}")
#             return {"fullName": "Không rõ tên", "department": "Không rõ phòng ban"}

#     def style_label(self, parent, text):
#         return tk.Label(parent, text=text, font=("Segoe UI", 10, "bold"), bg="#f9f9f9", anchor="w")

#     def create_widgets(self):
#         pad = {'padx': 12, 'pady': 8}
#         main = tk.Frame(self.master, bg="#f9f9f9")
#         main.pack(fill='both', expand=True, padx=30, pady=20)

#         tk.Label(main, text="📤 Gửi tài liệu", font=("Segoe UI", 18, "bold"), fg="#007BFF", bg="#f9f9f9").grid(row=0, column=0, columnspan=3, pady=20)

#         row = 1
#         # Họ tên
#         self.style_label(main, "Họ tên:").grid(row=row, column=0, sticky='w', **pad)
#         tk.Entry(main, state='disabled', width=40, disabledforeground="#555", disabledbackground="#eee",
#                  font=("Segoe UI", 10), justify="left", relief="flat",
#                  textvariable=tk.StringVar(value=self.user_info["fullName"])
#                  ).grid(row=row, column=1, columnspan=2, **pad)

#         # Department hiện tại của người dùng (không thể chỉnh sửa)
#         row += 1
#         self.style_label(main, "Phòng ban hiện tại:").grid(row=row, column=0, sticky='w', **pad)
#         tk.Entry(main, state='disabled', width=40, disabledforeground="#555", disabledbackground="#eee",
#                  font=("Segoe UI", 10), justify="left", relief="flat",
#                  textvariable=tk.StringVar(value=self.current_department)
#                  ).grid(row=row, column=1, columnspan=2, **pad)

#         # Loại tài liệu
#         row += 1
#         self.style_label(main, "Loại tài liệu:").grid(row=row, column=0, sticky='w', **pad)
#         self.doc_type_cb = ttk.Combobox(main, values=["internal", "external"], state='readonly', font=("Segoe UI", 10),
#                                         textvariable=self.doc_type_var)
#         self.doc_type_cb.grid(row=row, column=1, columnspan=2, **pad)
#         self.doc_type_cb.bind("<<ComboboxSelected>>", self.on_type_change)

#         # Department cho policy (chọn nhiều khi external, disabled và mặc định khi internal)
#         row += 1
#         self.style_label(main, "Chọn phòng ban cho policy:").grid(row=row, column=0, sticky='nw', **pad)
#         self.frame_policy_dept = tk.Frame(main, bg="#f9f9f9")
#         self.frame_policy_dept.grid(row=row, column=1, columnspan=2, sticky='w', **pad)

#         # Tạo list checkbox phòng ban policy
#         self.policy_dept_vars = {}
#         self.available_departments = ["IT", "SALES", "HR", "FINANCE"]
#         for dep in self.available_departments:
#             var = tk.BooleanVar()
#             cb = tk.Checkbutton(self.frame_policy_dept, text=dep, variable=var, bg="#e9ecef", font=("Segoe UI", 9),
#                                 onvalue=True, offvalue=False, command=self.on_policy_department_change)
#             cb.pack(side='left', padx=5, pady=2)
#             self.policy_dept_vars[dep] = (var, cb)

#         # Position (phụ thuộc department được chọn)
#         row += 1
#         self.style_label(main, "Chức vụ:").grid(row=row, column=0, sticky='nw', **pad)
#         self.frame_positions = tk.Frame(main, bg="#f9f9f9")
#         self.frame_positions.grid(row=row, column=1, columnspan=2, sticky='w', **pad)
#         self.position_vars = {}  # lưu biến checkbox theo chức vụ

#         # Public key
#         row += 1
#         self.style_label(main, "Chọn Public Key:").grid(row=row, column=0, sticky='w', **pad)
#         tk.Button(main, text="📂 Chọn", command=self.select_pubkey, bg="#17a2b8", fg="white").grid(row=row, column=1, sticky='w', **pad)
#         tk.Label(main, textvariable=self.pubkey_path, font=("Segoe UI", 9), bg="#f9f9f9", wraplength=300, anchor="w", justify="left").grid(row=row, column=2, sticky='w', **pad)

#         # File
#         row += 1
#         self.style_label(main, "Chọn File tài liệu:").grid(row=row, column=0, sticky='w', **pad)
#         tk.Button(main, text="📂 Chọn", command=self.select_file, bg="#17a2b8", fg="white").grid(row=row, column=1, sticky='w', **pad)
#         tk.Label(main, textvariable=self.file_path, font=("Segoe UI", 9), bg="#f9f9f9", wraplength=300, anchor="w", justify="left").grid(row=row, column=2, sticky='w', **pad)

#         # Tên tài liệu
#         row += 1
#         self.style_label(main, "Tên tài liệu:").grid(row=row, column=0, sticky='w', **pad)
#         self.entry_name = tk.Entry(main, width=40, font=("Segoe UI", 10))
#         self.entry_name.grid(row=row, column=1, columnspan=2, **pad)

#         # Location checkbox
#         row += 1
#         self.style_label(main, "Địa điểm:").grid(row=row, column=0, sticky='nw', **pad)
#         frame_location = tk.Frame(main, bg="#f9f9f9")
#         frame_location.grid(row=row, column=1, columnspan=2, sticky='w', **pad)
#         self.location_vars = []
#         for loc in ["HCM", "HN"]:
#             var = tk.BooleanVar()
#             tk.Checkbutton(frame_location, text=loc, variable=var, bg="#e9ecef", font=("Segoe UI", 9),
#                            onvalue=True, offvalue=False, command=self.build_policy).pack(side='left', padx=4, pady=2)
#             self.location_vars.append((loc, var))

#         # Role checkbox
#         row += 1
#         self.style_label(main, "Vai trò:").grid(row=row, column=0, sticky='nw', **pad)
#         frame_role = tk.Frame(main, bg="#f9f9f9")
#         frame_role.grid(row=row, column=1, columnspan=2, sticky='w', **pad)
#         self.role_vars = []
#         for role in ["MANAGER", "EMPLOYEE"]:
#             var = tk.BooleanVar()
#             tk.Checkbutton(frame_role, text=role, variable=var, bg="#e9ecef", font=("Segoe UI", 9),
#                            onvalue=True, offvalue=False, command=self.build_policy).pack(side='left', padx=4, pady=2)
#             self.role_vars.append((role, var))

#         # Policy hiển thị
#         row += 1
#         self.style_label(main, "Policy:").grid(row=row, column=0, sticky='w', **pad)
#         tk.Entry(main, textvariable=self.policy_var, width=50, state='readonly',
#                  font=("Segoe UI", 10)).grid(row=row, column=1, columnspan=2, **pad)

#         # Gửi
#         row += 1
#         tk.Button(main, text="Gửi", command=self.submit, bg="#28a745", fg="white", font=("Segoe UI", 11, "bold")).grid(row=row, column=0, columnspan=3, pady=20, ipadx=10, ipady=5)

#         # Khởi tạo trạng thái ban đầu
#         self.doc_type_cb.current(0)  # mặc định internal
#         self.set_policy_department_state()
#         self.update_positions()
#         self.build_policy()

#     def on_type_change(self, event=None):
#         self.set_policy_department_state()
#         self.build_policy()

#     def set_policy_department_state(self):
#         # Nếu internal thì không cho chọn department policy, tự động lấy current department
#         doc_type = self.doc_type_var.get()
#         if self.doc_type_var.get() == "internal":
#             pos_list = positions_map.get(self.current_department, [])
#         else:
#             # Nối tất cả position của các department được chọn
#             pos_list = []
#             for dep in self.policy_departments:
#                 pos_list.extend(positions_map.get(dep, []))
#             # Loại bỏ trùng lặp nếu cần
#             pos_list = list(dict.fromkeys(pos_list))

#         self.update_positions()

#     def on_policy_department_change(self):
#         # Khi user tick các department cho policy khi external
#         selected = [dep for dep, (var, cb) in self.policy_dept_vars.items() if var.get()]
#         self.policy_departments = selected
#         self.update_positions()
#         self.build_policy()

#     def update_positions(self):
#         if self.doc_type_var.get() == "internal":
#             pos_list = positions_map.get(self.current_department, [])
#         else:
#             pos_list = []
#             for dep in self.policy_departments:
#                 pos_list.extend(positions_map.get(dep, []))
#             # Loại bỏ trùng lặp nếu có
#             pos_list = list(dict.fromkeys(pos_list))

   

#         # Xóa các checkbox cũ
#         for widget in self.frame_positions.winfo_children():
#             widget.destroy()

#         self.position_vars = []

#         for pos in pos_list:
#             var = tk.BooleanVar()
#             cb = tk.Checkbutton(self.frame_positions, text=pos, variable=var, bg="#e9ecef", font=("Segoe UI", 9),
#                                 onvalue=True, offvalue=False, command=self.build_policy)
#             cb.pack(anchor='w')
#             self.position_vars.append((pos, var))

#     def select_pubkey(self):
#         path = filedialog.askopenfilename(title="Chọn file Public Key", filetypes=[("Public Key files", "*.pem *.key"), ("All files", "*.*")])
#         if path:
#             self.pubkey_path.set(path)

#     def select_file(self):
#         path = filedialog.askopenfilename(title="Chọn file tài liệu")
#         if path:
#             self.file_path.set(path)

#     def build_policy(self):
#         doc_type = self.doc_type_var.get()

#         if doc_type == "internal":
#             depts = [self.current_department]
#         else:
#             depts = self.policy_departments if self.policy_departments else []

#         locations = [loc for loc, var in self.location_vars if var.get()]

#         # Lấy tất cả positions được tick
#         positions = [pos for pos, var in self.position_vars if var.get()]

#         roles = [role for role, var in self.role_vars if var.get()] if hasattr(self, "role_vars") else []

#         parts = []

#         def format_group(items):
#             if not items:
#                 return ""
#             if len(items) == 1:
#                 return f"({items[0]})"
#             else:
#                 return "(" + " OR ".join(items) + ")"

#         dept_part = format_group(depts)
#         if dept_part:
#             parts.append(dept_part)

#         pos_part = format_group(positions)
#         if pos_part:
#             parts.append(pos_part)

#         loc_part = format_group(locations)
#         if loc_part:
#             parts.append(loc_part)

#         role_part = format_group(roles)
#         if role_part:
#             parts.append(role_part)

#         self.policy_var.set(" AND ".join(parts))
#     def submit(self):
#         if not self.pubkey_path.get():
#             messagebox.showwarning("Thiếu Public Key", "Vui lòng chọn file Public Key.")
#             return
#         if not self.file_path.get():
#             messagebox.showwarning("Thiếu File", "Vui lòng chọn file tài liệu.")
#             return
#         if not self.entry_name.get():
#             messagebox.showwarning("Thiếu Tên tài liệu", "Vui lòng nhập tên tài liệu.")
#             return
#         if not self.policy_var.get():
#             messagebox.showwarning("Thiếu Policy", "Policy không được để trống.")
#             return

#         try:
#             with open(self.pubkey_path.get(), "r", encoding="utf-8") as f:
#                 pubkey = f.read()
#             with open(self.file_path.get(), "rb") as f:
#                 file_data = f.read()

#             encrypted_data = encrypt(pubkey, file_data, self.policy_var.get())
#             save_to_firestore(encrypted_data, self.entry_name.get())
#             save_encrypted_message_to_firestore(
#             encrypted_data,
#             self.entry_name.get(),
#             ,
#             department,
#             doc_type
#         )
# def save_to_firestore(cipher_str: str, doc_name: str, owner: str, department: str, doc_type: str):
#     doc_ref = db.collection("messages").document()  
#     doc_data = {
#         "ciphertext": cipher_str,
#         "owner": owner,
#         "department": department,
#         "type": doc_type,
#         "name": doc_name if doc_name else doc_ref.id  
#     }

#     doc_ref.set(doc_data)
#     print(f"Document with ID {doc_ref.id} saved successfully.")

#             messagebox.showinfo("Thành công", "Gửi tài liệu thành công!")
#             self.master.destroy()
#         except Exception as e:
#             messagebox.showerror("Lỗi", f"Có lỗi khi gửi tài liệu: {e}")


# def run_upload_app(id_token):
#     root = tk.Tk()
#     app = UploadApp(root, id_token)
#     root.mainloop()

import os
save_path = os.getcwd()
if not os.path.exists(save_path):
    os.makedirs(save_path)
print(save_path)