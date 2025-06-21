import tkinter as tk
from tkinter import messagebox
import os
from connect import Client  
from a_cpabe import get_email_from_token,decrypt_document_local


class DocumentUI:
    def __init__(self, master, id_token, document_id):
        self.root = master
        self.id_token = id_token
        self.document_id = document_id
        self.client = Client(host='127.0.0.1', port=10023)

        self.root.title("📄 Document Viewer")
        self.root.geometry("900x720")

        self.button_get_sk = tk.Button(self.root, text="🔑 Lấy Secret Key", command=self.get_secret_key)
        self.button_get_sk.pack(pady=20, ipadx=10, ipady=5)

        self.button_get_pk = tk.Button(self.root, text="🔓 Lấy Public Key", command=self.get_public_key)
        self.button_get_pk.pack(pady=10, ipadx=10, ipady=5)

        self.button_decrypt = tk.Button(self.root, text="🗝️ Giải mã tài liệu", command=self.decrypt_document)
        self.button_decrypt.pack(pady=10, ipadx=10, ipady=5)


    def get_secret_key(self):
        if not self.id_token:
            messagebox.showerror("Lỗi", "Không có JWT hợp lệ để yêu cầu khóa.")
            return

        save_path = os.getcwd() 
        if not os.path.exists(save_path):
            os.makedirs(save_path)
        file_name = "private_key.bin"

        try:
            self.client.connect_to_server(
                mode='genkey',
                username=self.id_token,  
                save_path=save_path,
                file_name=file_name
            )
            messagebox.showinfo("Thành công", f"Đã nhận secret key tại:\n{save_path}/{file_name}")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể lấy secret key:\n{e}")


    def get_public_key(self):
        
        save_path = os.getcwd() 
        if not os.path.exists(save_path):
                os.makedirs(save_path)
        file_name = "public_key.bin"
        try:
            self.client.connect_to_server(mode='get_pub_key', save_path=save_path, file_name=file_name)
            print("Saving public key to:", os.path.join(save_path, file_name))
            messagebox.showinfo("Thành công", f"Đã nhận public key tại:\n{save_path}/{file_name}")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể lấy public key:\n{e}")
            
    def decrypt_document(self):
        try:
            secret_key_path = os.path.join(os.getcwd(), "private_key.bin")
            public_key_path = os.path.join(os.getcwd(), "public_key.bin")

            if not os.path.exists(secret_key_path) or not os.path.exists(public_key_path):
                messagebox.showerror("Lỗi", "Vui lòng đảm bảo đã có cả Secret Key và Public Key")
                return

            decrypted_bytes = decrypt_document_local(
                document_id=self.document_id,
                secret_key_path=secret_key_path,
                public_key_path=public_key_path
            )

            if decrypted_bytes is None:
                messagebox.showwarning("Thông báo", "Giải mã thành công nhưng đây là ảnh hoặc dữ liệu nhị phân.")
            else:
                messagebox.showinfo("Giải mã thành công", f"Nội dung tài liệu:\n{decrypted_bytes}")

        except Exception as e:
            messagebox.showerror("Lỗi", f"Giải mã thất bại:\n{e}")

if __name__ == "__main__":
    root = tk.Tk()
    id_token = ""
    document_id = ""
    app = DocumentUI(root, id_token, document_id)
    root.mainloop()
