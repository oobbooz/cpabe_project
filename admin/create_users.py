import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
import requests
from datetime import datetime

class CreateUserWindow:
    def __init__(self, root, jwt_token):
        self.root = root
        self.jwt_token = jwt_token
        self.root.title("Create Employee Accounts")
        self.root.geometry("1100x600")
        self.root.configure(bg="#f0f4ff")
        self.employees = []

        self.setup_ui()

    def setup_ui(self):
        tk.Label(
            self.root,
            text="Create Employee Accounts",
            font=("Segoe UI", 20, "bold"),
            bg="#f0f4ff",
            fg="#003366"
        ).pack(pady=20)

        btn_frame = tk.Frame(self.root, bg="#f0f4ff")
        btn_frame.pack(pady=10)

        tk.Button(
            btn_frame,
            text="Import CSV",
            command=self.import_csv,
            bg="#3366cc",
            fg="white",
            font=("Segoe UI", 12),
            padx=15,
            pady=5
        ).pack(side=tk.LEFT, padx=10)

        tk.Button(
            btn_frame,
            text="Send to Cloud",
            command=self.send_to_server,
            bg="#28a745",
            fg="white",
            font=("Segoe UI", 12),
            padx=15,
            pady=5
        ).pack(side=tk.LEFT, padx=10)

        columns = ("Email", "Password", "Full Name", "Department", "Location", "Position", "Role")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)

        self.tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    def import_csv(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return

        try:
            with open(file_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                self.employees.clear()
                self.tree.delete(*self.tree.get_children())

                for row in reader:
                    email = row.get("email", "").strip()
                    password = row.get("password", "").strip()
                    full_name = row.get("fullName", "").strip()
                    department = row.get("department", "").strip()
                    location = row.get("location", "").strip()
                    position = row.get("position", "").strip()
                    role = row.get("role", "EMPLOYEE").strip().upper()

                    if email and password:
                        user = {
                            "email": email,
                            "password": password,
                            "fullName": full_name,
                            "department": department,
                            "location": location,
                            "position": position,
                            "role": role,
                            "createdAt": datetime.utcnow().isoformat() + "Z"
                        }
                        self.employees.append(user)
                        self.tree.insert("", tk.END, values=(
                            email, password, full_name, department, location, position, role
                        ))
                    else:
                        print("Skipped invalid row:", row)

                messagebox.showinfo("Import Complete", f"Imported {len(self.employees)} users.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not import CSV:\n{e}")

    def send_to_server(self):
        if not self.employees:
            messagebox.showwarning("No Data", "Please import a CSV file first.")
            return

        try:
            url = "https://handle-request-itz4xkhbza-as.a.run.app"
            headers = {
                "Authorization": f"Bearer {self.jwt_token}",
                "Content-Type": "application/json"
            }
            payload = {
                "action": "create",
                "employees": self.employees
            }

            response = requests.post(url, headers=headers, json=payload)

            if response.status_code == 200:
                messagebox.showinfo("Success", "Employees created successfully.")
            else:
                messagebox.showerror("Error", f"Server responded with {response.status_code}:\n{response.text}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send data to server:\n{e}")
