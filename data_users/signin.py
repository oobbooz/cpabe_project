import tkinter as tk
from tkinter import ttk, messagebox
import requests
import os
from dotenv import load_dotenv

# Load biến môi trường từ .env
load_dotenv()
API_KEY = os.getenv("API_KEY")

# URL Firebase cho đăng nhập
SIGNIN_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"

class LoginWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Login to Your Account")
        self.root.geometry("900x700")
        self.root.configure(bg="#f0f4ff")
        self.root.resizable(False, False)

        self.setup_ui()

    def setup_ui(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TLabel", font=("Segoe UI", 13), background="#f0f4ff")
        style.configure("TEntry", font=("Segoe UI", 13))
        style.configure("TButton", font=("Segoe UI", 13, "bold"), padding=6)

        # Title label
        title = ttk.Label(self.root, text="Welcome Back", font=("Segoe UI", 20, "bold"), background="#f0f4ff", foreground="#003366")
        title.pack(pady=(50, 10))

        subtitle = ttk.Label(self.root, text="Please log in to continue", font=("Segoe UI", 14), background="#f0f4ff")
        subtitle.pack(pady=(0, 30))

        # Login Frame centered
        frame = ttk.Frame(self.root, padding=30)
        frame.pack(ipadx=20, ipady=20)

        # Email
        ttk.Label(frame, text="Email:").grid(row=0, column=0, sticky="w", padx=10, pady=10)
        self.entry_email = ttk.Entry(frame, width=40)
        self.entry_email.grid(row=0, column=1, padx=10, pady=10)

        # Password
        ttk.Label(frame, text="Password:").grid(row=1, column=0, sticky="w", padx=10, pady=10)
        self.entry_password = ttk.Entry(frame, width=40, show="*")
        self.entry_password.grid(row=1, column=1, padx=10, pady=10)

        # Login Button
        btn_login = ttk.Button(self.root, text="Login", command=self.sign_in)
        btn_login.pack(pady=(30, 10), ipadx=10, ipady=5)

        # Back to Sign Up
        btn_signup = ttk.Button(self.root, text="Back to Sign Up", command=self.back_to_signup)
        btn_signup.pack(pady=(0, 20), ipadx=10, ipady=5)

    def sign_in(self):
        email = self.entry_email.get().strip()
        password = self.entry_password.get().strip()

        if not email or not password:
            messagebox.showwarning("Missing Info", "Please enter both email and password.")
            return

        data = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }

        try:
            response = requests.post(SIGNIN_URL, json=data)
            response.raise_for_status()
            user = response.json()
        except requests.exceptions.HTTPError:
            try:
                error_code = response.json().get("error", {}).get("message", "")
            except:
                error_code = "UNKNOWN_ERROR"
            if error_code == "EMAIL_NOT_FOUND":
                messagebox.showerror("Error", "Email not found. Please sign up.")
            elif error_code == "INVALID_PASSWORD":
                messagebox.showerror("Error", "Wrong password.")
            else:
                messagebox.showerror("Error", f"Login failed: {error_code}")
            return
        except Exception as e:
            messagebox.showerror("Error", f"Network or server error:\n{str(e)}")
            return

        # Success
        id_token = user["idToken"]
        local_id = user["localId"]
        messagebox.showinfo("Success", f"Logged in successfully!\nUserID: {local_id}")

        self.root.destroy()

        # Mở giao diện encrypt trong cửa sổ mới
        self.open_decrypt_ui(id_token)

    def open_decrypt_ui(self, id_token):
        try:
            import decrypt_ui  
        except ImportError:
            messagebox.showerror("Error", "decrypt_ui module not found.")
            return

        new_root = tk.Tk()
        app = decrypt_ui.DecryptUI(new_root, id_token)
        new_root.mainloop()

    def back_to_signup(self):
        self.root.destroy()
        try:
            import signup
            signup.main()
        except ImportError:
            messagebox.showerror("Error", "signup module not found.")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    LoginWindow().run()
