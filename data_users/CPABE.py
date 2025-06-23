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

    def AC17decrypt(self,public_key, encrypted_data_b64: str, secret_key):
        encrypted_data = base64.b64decode(encrypted_data_b64.encode('utf-8'))
        len_encrypted_key = int.from_bytes(encrypted_data[:8], byteorder='big')
        encrypted_key_b = encrypted_data[8:8 + len_encrypted_key]
        ciphertext = encrypted_data[8 + len_encrypted_key:]
        encrypted_key = self.serialized.unjsonify_ctxt(encrypted_key_b.decode('utf-8'))
        recovered_random_key = self.ac17.decrypt(public_key, encrypted_key, secret_key)

        if recovered_random_key:
            nonce = ciphertext[:16]
            authTag = ciphertext[-16:]
            encrypted_content = ciphertext[16:-16]

            hash_obj = hashlib.sha256(str(recovered_random_key).encode('utf-8'))
            key = hash_obj.digest()
            try:
                aes = AES.new(key, AES.MODE_GCM, nonce)
                decrypted_bytes = aes.decrypt_and_verify(encrypted_content, authTag)
                return decrypted_bytes 
            except ValueError:
                return None
        else:
            return None