from a_cpabe import setup, gen_secret_key
from CPABE import CPABE
import socket
import ssl
import sys
import os
import json
from login_handler import handle_login_request  

class KGA:
    def __init__(self, host='127.0.0.1', port=10023, certfile=None, keyfile=None):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.is_running = True
        self.cpabe = CPABE("AC17")

    def KGAsetup(self, path):
        try:
            setup(self.cpabe, path)
            print('Setup successfully completed.')
        except Exception as e:
            print(f"Error during setup: {e}")

    def KGAgenkey(self, conn, addr, msg, public_key_file, master_key_file, private_key_file_path):
        try:
            mode, jwt_token = msg.split('|', 1)
            print(f"Mode: {mode}, jwt: {jwt_token}")
                       
            if mode == 'genkey':
                gen_secret_key(self.cpabe, public_key_file, master_key_file, jwt_token, private_key_file_path)
                
                with open(private_key_file_path, 'rb') as private_key_file:
                    private_key = private_key_file.read()
                    conn.sendall(private_key + b'END_OF_FILE')  

                print('Generated secret key for client:', addr)
            
        except Exception as e:
            print(f"Error generating secret key for {addr}: {e}")
        finally:
            if os.path.exists(private_key_file_path):
                os.remove(private_key_file_path)
            conn.close()
                
    def KGASendPubKey(self, conn, addr, public_key_file):
        try:
            with open(public_key_file, 'rb') as public_key_file:
                public_key = public_key_file.read()
                conn.sendall(public_key + b'END_OF_FILE')  

            print('Send public key for client:', addr)
        except Exception as e:
            print(f"Error sending public key to {addr}: {e}")
        finally:
            conn.close()

    def handle_request(self, conn, msg, addr):
        try:
            if msg == 'setup':
                self.KGAsetup("setup/")
            elif msg.startswith('genkey|'):
                self.KGAgenkey(
                    conn, addr, msg,
                    "resource/public_key.bin",
                    "resource/master_key.bin",
                    "resource/private_key.bin"
                )
            elif msg == 'get_pub_key':
                self.KGASendPubKey(conn, addr, "resource/public_key.bin")
            elif msg.startswith('login|'):
                try:
                    _, email, password = msg.split('|', 2)
                    payload = {"email": email, "password": password}
                    result = handle_login_request(payload)
                    conn.sendall(json.dumps(result).encode('utf-8'))
                    print(f"Login handled for {email}")
                except Exception as e:
                    err_msg = {"status": "error", "message": f"Invalid login format: {e}"}
                    conn.sendall(json.dumps(err_msg).encode('utf-8'))
            else:
                conn.sendall(b'Invalid choice')
                print(f"Invalid command from {addr}")
        except Exception as e:
            print(f"Error handling request from {addr}: {e}")
            conn.sendall(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))
        finally:
            conn.close()


    def start(self):
        setup_dir = "resource/"
        if not os.path.exists(setup_dir):
            os.makedirs(setup_dir)

        public_key_path = os.path.join(setup_dir, "public_key.bin")
        master_key_path = os.path.join(setup_dir, "master_key.bin")

        if not os.path.exists(public_key_path) or not os.path.exists(master_key_path):
            print("Chạy setup vì thiếu file khóa")
            self.KGAsetup(setup_dir)
        else:
            print("Khóa đã tồn tại, bỏ qua bước setup")

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"KGA listening on {self.host}:{self.port}")

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

        while self.is_running:
            try:
                conn, addr = server_socket.accept()
                conn = context.wrap_socket(conn, server_side=True)
                msg = conn.recv(1024).decode()
                self.handle_request(conn, msg, addr)
            except Exception as e:
                print(f"Error accepting connection: {e}")
                if conn:
                    conn.close()

        server_socket.close()
    
    def setup_key(self, path):
        self.KGAsetup(path)

if __name__ == "__main__":
    kga = KGA(certfile='localhost.crt', keyfile='localhost.key')
    kga.start()