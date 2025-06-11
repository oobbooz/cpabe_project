from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.ac17 import AC17CPABE
from Crypto.Cipher import AES
import hashlib
import base64
from SerializeCTXT import SerializeCTXT
class CPABE:
    def __init__(self, scheme):
        if scheme == "AC17":
            self.groupObj = PairingGroup("SS512")
            self.ac17 = AC17CPABE(self.groupObj, 2)
            self.serialized = SerializeCTXT()

    def AC17encrypt(self, public_key, message: bytes, policy):
        random_key = self.groupObj.random(GT)
        encrypted_key = self.ac17.encrypt(public_key, random_key, policy)
        encrypted_key_b = self.serialized.jsonify_ctxt(encrypted_key)

        hash = hashlib.sha256(str(random_key).encode())
        key = hash.digest()
        aes = AES.new(key, AES.MODE_GCM)

        ciphertext, authTag = aes.encrypt_and_digest(message)
        nonce = aes.nonce
        print(len(nonce))

        ciphertext = nonce + ciphertext + authTag
        len_encrypted_data = len(encrypted_key_b)
        encrypted_data = len_encrypted_data.to_bytes(8, byteorder='big') + encrypted_key_b.encode() + ciphertext
        encrypted_data_b64 = base64.b64encode(encrypted_data).decode()
        return encrypted_data_b64
    
    def deserialize_public_key(self, public_key_bytes):
        return bytesToObject(public_key_bytes, self.groupObj)