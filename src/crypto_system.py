from kyber_wrapper import Kyber768
from dilithium_wrapper import Dilithium3
from aes_handler import AESHandler

class SecureChannel:
    """Complete post-quantum secure communication channel"""
    
    def __init__(self):
        self.kyber = Kyber768()
        self.dilithium = Dilithium3()
        self.aes = AESHandler()
    
    def generate_keys(self):
        """Generate both Kyber and Dilithium keypairs"""
        kem_pk, kem_sk = self.kyber.keypair()
        sign_pk, sign_sk = self.dilithium.keypair()
        
        return {
            'kem_public': kem_pk,
            'kem_secret': kem_sk,
            'sign_public': sign_pk,
            'sign_secret': sign_sk
        }
    
    def send_message(self, message, recipient_kem_pk, sender_sign_sk):
        """
        Encrypt and sign a message
        Returns: (ciphertext, signature, kyber_ciphertext)
        """
        # 1. Use Kyber to establish shared secret
        kyber_ct, shared_secret = self.kyber.encapsulate(recipient_kem_pk)
        
        # 2. Encrypt message with AES-GCM using shared secret
        encrypted_msg = self.aes.encrypt(message, shared_secret)
        
        # 3. Sign the encrypted message with Dilithium
        signature = self.dilithium.sign(encrypted_msg, sender_sign_sk)
        
        return {
            'encrypted_message': encrypted_msg,
            'signature': signature,
            'kyber_ciphertext': kyber_ct
        }
    
    def receive_message(self, package, recipient_kem_sk, sender_sign_pk):
        """
        Verify and decrypt a message
        Returns: plaintext message
        """
        encrypted_msg = package['encrypted_message']
        signature = package['signature']
        kyber_ct = package['kyber_ciphertext']
        
        # 1. Verify signature first
        if not self.dilithium.verify(signature, encrypted_msg, sender_sign_pk):
            raise ValueError("Signature verification failed! Message may be tampered.")
        
        # 2. Recover shared secret using Kyber
        shared_secret = self.kyber.decapsulate(kyber_ct, recipient_kem_sk)
        
        # 3. Decrypt message with AES-GCM
        plaintext = self.aes.decrypt(encrypted_msg, shared_secret)
        
        return plaintext.decode('utf-8')