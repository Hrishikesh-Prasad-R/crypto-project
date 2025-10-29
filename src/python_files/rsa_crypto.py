"""
RSA Cryptography Implementation
Classical cryptography for comparison with post-quantum algorithms

FILE: rsa_crypto.py
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import time


class RSACrypto:
    """RSA implementation for encryption and digital signatures"""
    
    def __init__(self, key_size=2048):
        """
        Initialize RSA crypto system
        
        Args:
            key_size: RSA key size in bits (2048, 3072, or 4096)
        """
        self.key_size = key_size
    
    def generate_keypair(self):
        """
        Generate RSA keypair
        
        Returns:
            tuple: (public_key, private_key) as PEM-encoded bytes
        """
        start_time = time.time()
        key = RSA.generate(self.key_size)
        generation_time = time.time() - start_time
        
        public_key = key.publickey().export_key()
        private_key = key.export_key()
        
        return public_key, private_key, generation_time
    
    def encrypt(self, message, public_key_pem):
        """
        Encrypt a message using RSA-OAEP
        
        Args:
            message: bytes or string to encrypt
            public_key_pem: PEM-encoded public key
            
        Returns:
            tuple: (ciphertext, encryption_time)
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # RSA can only encrypt small messages
        # For larger messages, we'd need hybrid encryption
        if len(message) > (self.key_size // 8) - 42:  # OAEP overhead
            raise ValueError(f"Message too long for RSA-{self.key_size}. Max: {(self.key_size // 8) - 42} bytes")
        
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(public_key)
        
        start_time = time.time()
        ciphertext = cipher.encrypt(message)
        encryption_time = time.time() - start_time
        
        return ciphertext, encryption_time
    
    def decrypt(self, ciphertext, private_key_pem):
        """
        Decrypt a message using RSA-OAEP
        
        Args:
            ciphertext: encrypted bytes
            private_key_pem: PEM-encoded private key
            
        Returns:
            tuple: (plaintext, decryption_time)
        """
        private_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(private_key)
        
        start_time = time.time()
        plaintext = cipher.decrypt(ciphertext)
        decryption_time = time.time() - start_time
        
        return plaintext, decryption_time
    
    def sign(self, message, private_key_pem):
        """
        Create a digital signature using RSA-PSS
        
        Args:
            message: bytes or string to sign
            private_key_pem: PEM-encoded private key
            
        Returns:
            tuple: (signature, signing_time)
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        private_key = RSA.import_key(private_key_pem)
        h = SHA256.new(message)
        
        start_time = time.time()
        signature = pkcs1_15.new(private_key).sign(h)
        signing_time = time.time() - start_time
        
        return signature, signing_time
    
    def verify(self, signature, message, public_key_pem):
        """
        Verify a digital signature
        
        Args:
            signature: signature bytes
            message: original message bytes or string
            public_key_pem: PEM-encoded public key
            
        Returns:
            tuple: (is_valid, verification_time)
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        public_key = RSA.import_key(public_key_pem)
        h = SHA256.new(message)
        
        start_time = time.time()
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            is_valid = True
        except (ValueError, TypeError):
            is_valid = False
        verification_time = time.time() - start_time
        
        return is_valid, verification_time
    
    def get_key_sizes(self, public_key_pem, private_key_pem):
        """
        Get the sizes of RSA keys
        
        Returns:
            dict: key sizes in bytes
        """
        return {
            'public_key': len(public_key_pem),
            'private_key': len(private_key_pem),
            'signature': self.key_size // 8,  # RSA signature size
            'ciphertext': self.key_size // 8   # RSA ciphertext size
        }