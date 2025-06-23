import tkinter as tk
from tkinter import ttk, messagebox
from connect import Client  
import json 

class LoginWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Login to Your Account")
        self.root.geometry("900x500")
        self.root.configure(bg="#f0f4ff")
        self.root.resizable(False, False)

        self.client = Client(host='127.0.0.1', port=10023)  

        self.setup_ui()

    def setup_ui(self):
        
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TLabel", font=("Segoe UI", 13), background="#f0f4ff")
        style.configure("TEntry", font=("Segoe UI", 13))
        style.configure("TButton", font=("Segoe UI", 13, "bold"), padding=6)

        title = ttk.Label(
            self.root,
            text="Welcome Back",
            font=("Segoe UI", 20, "bold"),
            background="#f0f4ff",
            foreground="#003366"
        )
        title.pack(pady=(50, 10))

        subtitle = ttk.Label(
            self.root,
            text="Please log in to continue",
            font=("Segoe UI", 14),
            background="#f0f4ff"
        )
        subtitle.pack(pady=(0, 30))

        frame = ttk.Frame(self.root, padding=30)
        frame.pack(ipadx=20, ipady=20)

        ttk.Label(frame, text="Email:").grid(row=0, column=0, sticky="w", padx=10, pady=10)
        self.entry_email = ttk.Entry(frame, width=40)
        self.entry_email.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(frame, text="Password:").grid(row=1, column=0, sticky="w", padx=10, pady=10)
        self.entry_password = ttk.Entry(frame, width=40, show="*")
        self.entry_password.grid(row=1, column=1, padx=10, pady=10)

        btn_login = ttk.Button(self.root, text="Login", command=self.sign_in)
        btn_login.pack(pady=(30, 10), ipadx=10, ipady=5)


    def sign_in(self):
        email = self.entry_email.get().strip()
        password = self.entry_password.get().strip()

        if not email or not password:
            messagebox.showwarning("Missing Information", "Please enter both email and password.")
            return

        try:
            raw_response = self.client.connect_to_server(
                mode='login',
                username=email,
                save_path=password
            )

            print("Raw response:", raw_response)  

            if raw_response:
                try:
                    response = json.loads(raw_response)
                    if isinstance(response, dict) and response.get("status") == "ok" and "jwt" in response:
                        jwt_token = response["jwt"]
                        messagebox.showinfo("Success", "Login successful!")
                        self.root.destroy()
                        self.open_encrypt(jwt_token)
                    else:
                        messagebox.showerror("Login Failed", f"Error: {response.get('message', 'Login unsuccessful.')}")
                except json.JSONDecodeError:
                    if raw_response.startswith("eyJ"):  
                        jwt_token = raw_response
                        messagebox.showinfo("Success", "Login successful!")
                        self.root.destroy()
                        self.open_encrypt(jwt_token)
                    else:
                        messagebox.showerror("Error", "Invalid response from server.")
            else:
                messagebox.showerror("Error", "No response from server.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during login request:\n{e}")

    def open_encrypt(self, id_token):
        try:
            import encrypt
        except ImportError:
            messagebox.showerror("Error", "Module 'encrypt' not found.")
            return

        new_root = tk.Tk()
        app = encrypt.UploadApp(new_root, id_token)
        new_root.mainloop()


    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    LoginWindow().run()
