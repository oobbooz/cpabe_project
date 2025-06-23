import socket
import ssl
import json
import os

class AdminClient:
    def __init__(self, host='127.0.0.1', port=10023):
        self.host = host
        self.port = port

    def login(self, email, password):
        try:
            context = ssl._create_unverified_context() 
            conn = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=self.host)
            conn.connect((self.host, self.port))

            message = f"login|{email}|{password}"
            conn.sendall(message.encode('utf-8'))

            response = conn.recv(4096).decode('utf-8')
            print("Raw response:", response)

            try:
                result = json.loads(response)
                if result.get("status") == "ok":
                    return result.get("jwt")
                else:
                    print("Login failed:", result.get("message"))
                    return None
            except json.JSONDecodeError:
                print("Invalid JSON response from server.")
                return None
            finally:
                conn.close()

        except Exception as e:
            print("Login error:", str(e))
            return None


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 5:
        sys.exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])
    email = sys.argv[3]
    password = sys.argv[4]

    client = AdminClient(host=ip, port=port)
    jwt_token = client.login(email, password)

    if jwt_token:
        print("JWT received:", jwt_token)
    else:
        print("Failed to login.")
