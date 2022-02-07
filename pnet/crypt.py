"""
PNET - Local p2p protocol

(c) Dax Harris 2021
MIT License
"""

import rsa
import rsa.pkcs1
from cryptography.fernet import Fernet
import base64
import pickle
import random
import typing

def universal_encode(data: typing.Any) -> bytes:
    """
    Encodes any data into base64
    Yes, any data
    All the data
    :data The data
    -> The encoded data
    """
    if type(data) == str:
        _data: bytes = data.encode("utf-8")
        _fmt = b"str"
    elif type(data) == bytes:
        _data: bytes = data
        _fmt = b"raw"
    else:
        _data: bytes = pickle.dumps(data)
        _fmt = b"pkl"
    return base64.urlsafe_b64encode(_fmt+b"|"+_data)

def universal_decode(data: bytes | str) -> typing.Any:
    if type(data) == str:
        data = data.encode("utf-8")
    if b"|" in data:
        data = base64.urlsafe_b64encode(data)
    data = base64.urlsafe_b64decode(data)
    fmt, data = data.split(b"|", maxsplit=1)
    if fmt == b"raw":
        return data
    elif fmt == b"str":
        return data.decode("utf-8")
    else:
        return pickle.loads(data)
    

class Crypt:
    def __init__(self, keys: list[rsa.PublicKey | rsa.PrivateKey] | None | int = None, keygen_chance: float = 0.05):
        """
        Cryptography class for encryption
        :keys Any of [publicKey, privateKey], None (generates 256-bit keys), int n (generates n-bit keys)
        :keygen_chance The chance, per-packet, that the Fernet key will be regenerated - out of 1.0
        """
        if keys == None:
            (self.public, self.private) = rsa.newkeys(512)
        elif type(keys) == int:
            (self.public, self.private) = rsa.newkeys(keys)
        elif type(keys) == list and len(keys) == 2 and isinstance(keys[0], rsa.PublicKey) and isinstance(keys[1], rsa.PrivateKey):
            self.public = keys[0]
            self.private = keys[1]
        else:
            raise ValueError(f"Invalid keys: {keys}")
        
        self.kchance = keygen_chance
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)

    def encrypt(self, data: typing.Any, pk: rsa.PublicKey) -> bytes:
        """
        Encrypts data
        :data Any object. Str will be encoded, bytes will be used as-is, and anything else will be pickled.
        :pk Recipient public key
        -> base64 data
        """
        all_data = universal_encode(data)
        
        # Regenerates key randomly
        if random.random() < self.kchance:
            self.key = Fernet.generate_key()
            self.fernet = Fernet(self.key)
        
        data_encrypted = base64.urlsafe_b64encode(self.fernet.encrypt(all_data))
        enc_key = base64.urlsafe_b64encode(rsa.encrypt(self.key, pk))
        data_encoded = base64.urlsafe_b64encode(enc_key + b"|" + data_encrypted)
        return data_encoded
    
    def decrypt(self, data: str | bytes) -> typing.Any:
        """
        Decrypts data
        :data base64-encoded string or bytes
        -> Decrypted object
        """
        if type(data) == str:
            data = data.encode("utf-8")
        
        decdata = base64.urlsafe_b64decode(data)
        ekey, edata = decdata.split(b"|", maxsplit=1)
        key = rsa.decrypt(base64.urlsafe_b64decode(ekey), self.private)
        decryptor = Fernet(key)
        return universal_decode(decryptor.decrypt(base64.urlsafe_b64decode(edata)))