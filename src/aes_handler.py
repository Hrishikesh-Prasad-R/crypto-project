from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class AESHandler:
    """AES-256-GCM encryption/decryption using 32-byte key from Kyber"""
    
    @staticmethod
    def encrypt(plaintext, key):
        """Encrypt plaintext with AES-256-GCM"""
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256")
        
        # Convert string to bytes if needed
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        # Return nonce + tag + ciphertext
        return cipher.nonce + tag + ciphertext
    
    @staticmethod
    def decrypt(encrypted_data, key):
        """Decrypt ciphertext with AES-256-GCM"""
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256")
        
        # Extract nonce (16 bytes), tag (16 bytes), and ciphertext
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext