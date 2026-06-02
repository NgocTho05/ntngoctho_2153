import rsa
import os

KEYS_DIR = os.path.join(os.path.dirname(__file__), 'keys')


class RSACipher:
    def __init__(self):
        os.makedirs(KEYS_DIR, exist_ok=True)

    def generate_keys(self, key_size=2048):
        public_key, private_key = rsa.newkeys(key_size)
        with open(os.path.join(KEYS_DIR, 'public.pem'), 'wb') as f:
            f.write(public_key.save_pkcs1())
        with open(os.path.join(KEYS_DIR, 'private.pem'), 'wb') as f:
            f.write(private_key.save_pkcs1())

    def load_keys(self):
        with open(os.path.join(KEYS_DIR, 'private.pem'), 'rb') as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())
        with open(os.path.join(KEYS_DIR, 'public.pem'), 'rb') as f:
            public_key = rsa.PublicKey.load_pkcs1(f.read())
        return private_key, public_key

    def encrypt(self, message, key):
        if isinstance(message, str):
            message = message.encode('utf-8')
        return rsa.encrypt(message, key)

    def decrypt(self, ciphertext, key):
        return rsa.decrypt(ciphertext, key).decode('utf-8')

    def sign(self, message, private_key):
        if isinstance(message, str):
            message = message.encode('utf-8')
        return rsa.sign(message, private_key, 'SHA-256')

    def verify(self, message, signature, public_key):
        if isinstance(message, str):
            message = message.encode('utf-8')
        try:
            rsa.verify(message, signature, public_key)
            return True
        except rsa.VerificationError:
            return False
