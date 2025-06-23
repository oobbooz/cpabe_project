from CPABE import CPABE
import argparse
from charm.toolbox.pairinggroup import PairingGroup
from charm.core.engine.util import objectToBytes, bytesToObject
import sys
import shutil
from jwt.exceptions import InvalidTokenError
import jwt  

def read_input_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    input_data = {}
    for line in lines:
        key, value = line.strip().split(': ', 1)
        input_data[key] = value
    
    return input_data

def save_to_file(data, filename):
    with open(filename, 'wb') as file:
        file.write(data)

def load_from_file(filename):
    with open(filename, 'rb') as file:
        return file.read()

def setup(cpabe, path):
    public_key, master_key = cpabe.ac17.setup()
    
    serialized_public_key = objectToBytes(public_key, cpabe.groupObj)
    serialized_master_key = objectToBytes(master_key, cpabe.groupObj)
    
    save_to_file(serialized_public_key, path+'public_key.bin')
    save_to_file(serialized_master_key, path+'master_key.bin')
    
    print(f"Keys generated and saved to {path}public_key.bin and {path}master_key.bin")


def gen_secret_key(cpabe, public_key_file, master_key_file, jwt_token, private_key_file):
    try:
        public_key = bytesToObject(load_from_file(public_key_file), cpabe.groupObj)
        master_key = bytesToObject(load_from_file(master_key_file), cpabe.groupObj)

        with open("resource/ecdsa_public.pem", "r") as f:
            ca_public_key = f.read()

        payload = jwt.decode(jwt_token, ca_public_key, algorithms=["ES256"])
        
        attrs = [
            payload.get("position", ""),
            payload.get("role", ""),
            payload.get("department", ""),
            payload.get("location", "")
        ]
        user_attributes = [attr for attr in attrs if attr]  

        print("User attributes:", user_attributes)

        private_key = cpabe.ac17.keygen(public_key, master_key, user_attributes)
        serialized_private_key = objectToBytes(private_key, cpabe.groupObj)
        save_to_file(serialized_private_key, private_key_file)
        
    except InvalidTokenError as e:
        print("JWT không hợp lệ:", str(e))
        raise
    except Exception as e:
        print("Lỗi tạo khóa:", str(e))
        raise
    
def main():
    cpabe = CPABE("AC17")

    setup(cpabe, './keys/')

    gen_secret_key(cpabe,
                   public_key_file='./keys/public_key.bin',
                   master_key_file='./keys/master_key.bin',
                   attributes='ATTR1,ATTR2',
                   private_key_file='./keys/private_key.bin')

if __name__ == "__main__":
    main()