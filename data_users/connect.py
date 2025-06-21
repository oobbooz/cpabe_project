import socket
import ssl
import sys
import os
from google.cloud import firestore
import json
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "/home/bo/Documents/new/data_users/resource/serviceAccount.json"
sys.path.append(parent_dir)
class Client:
    def __init__(self, host='127.0.0.1', port=10023):
        self.host = host
        self.port = port
    
    def send_login_request(self, conn, email, password):
        try:
            message = f"login|{email}|{password}"
            conn.sendall(message.encode('utf-8'))

            response = conn.recv(4096).decode('utf-8')
            print("Raw response:", response)

            result = json.loads(response)

            if result.get("status") == "ok":
                return result.get("jwt")
            else:
                print(" Login failed:", result.get("message"))
                return None

        except json.JSONDecodeError:
            print(" Error decoding response: Not valid JSON")
            return None
        except Exception as e:
            print(" Unexpected error during login:", str(e))
            return None
        finally:
            conn.close()

    def get_attributes_from_db(self, email):
        db = firestore.Client()

        employees_ref = db.collection("users")

        query = employees_ref.where("email", "==", email).limit(1)
        results = query.stream()

        for doc in results:
            data = doc.to_dict()
            position = data.get("position", "")
            role = data.get("role", "")
            department = data.get("department", "")
            location = data.get("location", "")
            return f"{position},{role},{department},{location}"

        return None
        
    def send_genkey_request(self, conn, jwt_token, save_path, file_name):
        mode = 'genkey'
        message = f"{mode}|{jwt_token}"
        print(f"[📤] Sending JWT to CA for SK generation...")

        conn.sendall(message.encode('utf-8'))

        with open(os.path.join(save_path, file_name), 'wb') as f:
            while True:
                data = conn.recv(1024)
                if b'END_OF_FILE' in data:
                    f.write(data.replace(b'END_OF_FILE', b''))
                    break
                f.write(data)

        print("✅ Secret key received and saved successfully.")
        conn.close()


    
    def connect_to_server(self, mode, username=None, save_path=None, file_name=None):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        certificate_path = os.path.join(current_dir, "resource", "localhost.crt")
        context.load_verify_locations(certificate_path)
        context.check_hostname = False
        context = ssl._create_unverified_context()
        print("Connected to the kga")
        try:
            conn = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=self.host)
            conn.connect((self.host, self.port))
            if conn.cipher():
                print("Connection is encrypted with:", conn.cipher()[0])
            else:
                print("Connection is not encrypted.")

            if mode == 'setup':
                if save_path is None or file_name is None:
                    print("Please provide save path and file name.")
                    conn.close()
                    return 

                conn.sendall(mode.encode('utf-8'))
                with open(os.path.join(save_path, file_name), 'wb') as f:
                    while True:
                        data = conn.recv(1024)
                        if b'END_OF_FILE' in data:
                            f.write(data.replace(b'END_OF_FILE', b''))
                            break
                        f.write(data)
                print("File received successfully.")
                conn.close()
                return  
            elif mode == 'genkey':
                if username is None or save_path is None or file_name is None:
                    print("Please provide username, save path, and file name.")
                    conn.close()
                    return  
                self.send_genkey_request(conn, username, save_path, file_name)
            
            elif mode == 'get_pub_key':
                if save_path is None or file_name is None:
                    print("Please provide save path and file name.")
                    conn.close()
                    return 

                conn.sendall(mode.encode('utf-8'))
                with open(os.path.join(save_path, file_name), 'wb') as f:
                    while True:
                        data = conn.recv(1024)
                        if b'END_OF_FILE' in data:
                            f.write(data.replace(b'END_OF_FILE', b''))
                            break
                        f.write(data)
                print("File received successfully.")
                conn.close()
                return  
            elif mode == 'login':
                if username is None or save_path is None:
                    print("Please provide email (as username) and password (as save_path).")
                    conn.close()
                    return
                return self.send_login_request(conn, username, save_path)
            

        except Exception as e:
            print("Error:", e)
            conn.close()
            return  

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 client.py <server_ip> <server_port> [setup|genkey|get_pub_key] <additional_args>")
        sys.exit(1)
        
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    mode = sys.argv[3]
    client = Client(host=server_ip, port=server_port)
    
    if mode == 'setup':
        if len(sys.argv) != 6:
            print("Usage: python3 client.py <server_ip> <server_port> setup <path_to_save> <file_name>")
            sys.exit(1)
        client.connect_to_server(mode, None, sys.argv[4], sys.argv[5])
    elif mode == 'genkey':
        if len(sys.argv) != 7:
            print("Usage: python3 client.py <server_ip> <server_port> genkey <username> <path_to_save> <file_name>")
            sys.exit(1)
        username = sys.argv[4]
        client.connect_to_server(mode, username, sys.argv[5], sys.argv[6])
    elif mode == 'get_pub_key':
        if len(sys.argv) != 6:
            print("Usage: python3 client.py <server_ip> <server_port> get_pub_key <path_to_save> <file_name>")
            sys.exit(1)
        client.connect_to_server(mode, None, sys.argv[4], sys.argv[5])
    elif mode == 'login':
        if len(sys.argv) != 6:
            print("Usage: python3 connect.py <server_ip> <server_port> login <email> <password>")
            sys.exit(1)
        email = sys.argv[4]
        password = sys.argv[5]
       
        client.connect_to_server(mode, email, password)
