import tkinter as tk
from tkinter import messagebox
import os
import requests
from connect import Client
from a_cpabe import decrypt
from PIL import Image, ImageTk
import io

class DecryptUI:
    def __init__(self, master, id_token, document_id, department):
        self.root = master
        self.id_token = id_token
        self.document_id = document_id
        self.department = department
        self.client = Client(host='127.0.0.1', port=10023)

        self.root.title("Document Viewer")
        self.root.geometry("1000x1000")
        self.root.configure(bg="#f0f4ff")

        self.create_widgets()

    def create_widgets(self):
        title = tk.Label(
            self.root,
            text="🔐 Decrypt Document",
            font=("Segoe UI", 24, "bold"),
            bg="#f0f4ff",
            fg="#003366"
        )
        title.pack(pady=(30, 20))

        button_frame = tk.Frame(self.root, bg="#f0f4ff")
        button_frame.pack(pady=10)

        btn_style = {
            "width": 20,
            "height": 2,
            "font": ("Segoe UI", 12, "bold"),
            "bg": "#3366cc",
            "fg": "white",
            "activebackground": "#5588dd",
            "activeforeground": "white",
            "bd": 0
        }

        self.button_get_sk = tk.Button(button_frame, text="🔑 Get Secret Key", command=self.get_secret_key, **btn_style)
        self.button_get_sk.pack(pady=10)

        self.button_get_pk = tk.Button(button_frame, text="🔓 Get Public Key", command=self.get_public_key, **btn_style)
        self.button_get_pk.pack(pady=10)

        self.button_decrypt = tk.Button(button_frame, text="🗝️ Decrypt Document", command=self.decrypt_document, **btn_style)
        self.button_decrypt.pack(pady=10)

        self.output_text = tk.Text(self.root, height=40, font=("Arial", 12), wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=False, padx=30, pady=(20, 10))
        self.output_text.configure(state=tk.DISABLED)

        self.image_frame = tk.Frame(self.root, bg="#f0f4ff")
        self.image_frame.pack(pady=(10, 20))

    def get_secret_key(self):
        if not self.id_token:
            messagebox.showerror("Error", "No valid JWT to request the key.")
            return

        save_path = os.path.join(os.getcwd(), "resource")
        os.makedirs(save_path, exist_ok=True)
        file_name = "secret_key.bin"

        try:
            self.client.connect_to_server(
                mode='genkey',
                username=self.id_token,
                save_path=save_path,
                file_name=file_name
            )
            messagebox.showinfo("Success", f"Secret key saved to:\n{save_path}/{file_name}",parent=self.root)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get secret key:\n{e}")

    def get_public_key(self):
        save_path = os.path.join(os.getcwd(), "resource")
        os.makedirs(save_path, exist_ok=True)
        file_name = "public_key.bin"

        try:
            self.client.connect_to_server(
                mode='get_pub_key',
                save_path=save_path,
                file_name=file_name
            )
            messagebox.showinfo("Success", f"Public key saved to:\n{save_path}/{file_name}",parent=self.root)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get public key:\n{e}")

    def display_text(self, content):
        self.image_frame.pack_forget()  
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=30, pady=(20, 10))

        self.output_text.configure(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, content)
        self.output_text.configure(state=tk.DISABLED)

    def display_image(self, image_data):
        self.output_text.pack_forget()  
        self.image_frame.pack(pady=(10, 20))

        for widget in self.image_frame.winfo_children():
            widget.destroy()

        try:
            image = Image.open(io.BytesIO(image_data))
            image.thumbnail((800, 800), Image.Resampling.LANCZOS)
            img = ImageTk.PhotoImage(image)

            canvas = tk.Canvas(self.image_frame, width=image.width, height=image.height, bg="white", bd=1, relief="solid")
            canvas.pack()
            canvas.create_image(0, 0, anchor=tk.NW, image=img)
            canvas.image = img  
        except Exception as e:
            messagebox.showwarning("Error", f"Failed to display image:\n{e}")

    def decrypt_document(self):
        try:
            secret_key_path = os.path.join(os.getcwd(), "resource", "secret_key.bin")
            public_key_path = os.path.join(os.getcwd(), "resource", "public_key.bin")

            if not os.path.exists(secret_key_path) or not os.path.exists(public_key_path):
                messagebox.showerror("Error", "Please make sure both Secret Key and Public Key exist.")
                return

            function_url = "https://handle-request-itz4xkhbza-as.a.run.app"
            headers = {
                "Authorization": f"Bearer {self.id_token}",
                "Content-Type": "application/json"
            }
            payload = {
                "action": "read",
                "resource": {
                    "doc_id": self.document_id,
                }
            }

            response = requests.post(function_url, headers=headers, json=payload)

            if response.status_code != 200:
                messagebox.showerror("Error", f"Failed to retrieve document: {response.status_code}")
                return

            try:
                doc_data = response.json()
            except Exception as e:
                messagebox.showerror("Error", f"JSON parsing failed: {e}")
                return

            ciphertext = doc_data.get("ciphertext")
            if not ciphertext:
                messagebox.showerror("Error", "No ciphertext found.")
                return

            decrypted_data = decrypt(
                ciphertext=ciphertext,
                secret_key_path=secret_key_path,
                public_key_path=public_key_path
            )

            if decrypted_data is None:
                messagebox.showinfo("Notice", "Decryption successful, but content is binary or image.")
                return

            if isinstance(decrypted_data, bytes):
                try:
                    text = decrypted_data.decode('utf-8')
                    self.display_text(text)
                except UnicodeDecodeError:
                    self.display_image(decrypted_data)
                return

            elif isinstance(decrypted_data, str):
                self.display_text(decrypted_data)
                return

            messagebox.showinfo("Notice", "Decrypted data format unknown.")

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        token = sys.argv[1]
        doc_id = sys.argv[2]
    else:
        print("Missing token or doc_id argument")
        sys.exit(1)

    root = tk.Tk()
    app = DecryptUI(root, token, doc_id, department=None)
    root.mainloop()
