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