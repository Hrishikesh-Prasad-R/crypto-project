import ctypes
import os
import platform
from pathlib import Path

# Constants for Kyber768
KYBER768_PUBLICKEYBYTES = 1184
KYBER768_SECRETKEYBYTES = 2400
KYBER768_CIPHERTEXTBYTES = 1088
KYBER768_BYTES = 32  # Shared secret size

class Kyber768:
    def __init__(self):
        # Load the DLL
        system = platform.system()
        base_dir = Path(__file__).parent  # directory of this wrapper file

        if system == "Windows":
            lib_path = base_dir / "libpqcrystals_kyber768_ref.dll"
        elif system == "Linux":
            lib_path = base_dir / "libpqcrystals_kyber768_ref.so"
        else:
            raise RuntimeError(f"Unsupported OS: {system}")

        if not lib_path.exists():
            raise FileNotFoundError(f"Library not found: {lib_path}")

        # Load the shared library
        self.lib = ctypes.CDLL(str(lib_path))
        
        # Define function signatures
        # int pqcrystals_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk)
        self.lib.pqcrystals_kyber768_ref_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.lib.pqcrystals_kyber768_ref_keypair.restype = ctypes.c_int
        
        # int pqcrystals_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
        self.lib.pqcrystals_kyber768_ref_enc.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.lib.pqcrystals_kyber768_ref_enc.restype = ctypes.c_int
        
        # int pqcrystals_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
        self.lib.pqcrystals_kyber768_ref_dec.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.lib.pqcrystals_kyber768_ref_dec.restype = ctypes.c_int
    
    def keypair(self):
        """Generate a Kyber768 keypair"""
        pk = (ctypes.c_uint8 * KYBER768_PUBLICKEYBYTES)()
        sk = (ctypes.c_uint8 * KYBER768_SECRETKEYBYTES)()
        
        result = self.lib.pqcrystals_kyber768_ref_keypair(pk, sk)
        if result != 0:
            raise RuntimeError(f"Kyber768 keypair generation failed with code {result}")
        
        return bytes(pk), bytes(sk)
    
    def encapsulate(self, public_key):
        """Encapsulate to create shared secret and ciphertext"""
        if len(public_key) != KYBER768_PUBLICKEYBYTES:
            raise ValueError(f"Public key must be {KYBER768_PUBLICKEYBYTES} bytes")
        
        ct = (ctypes.c_uint8 * KYBER768_CIPHERTEXTBYTES)()
        ss = (ctypes.c_uint8 * KYBER768_BYTES)()
        pk = (ctypes.c_uint8 * KYBER768_PUBLICKEYBYTES)(*public_key)
        
        result = self.lib.pqcrystals_kyber768_ref_enc(ct, ss, pk)
        if result != 0:
            raise RuntimeError(f"Kyber768 encapsulation failed with code {result}")
        
        return bytes(ct), bytes(ss)
    
    def decapsulate(self, ciphertext, secret_key):
        """Decapsulate to recover shared secret"""
        if len(ciphertext) != KYBER768_CIPHERTEXTBYTES:
            raise ValueError(f"Ciphertext must be {KYBER768_CIPHERTEXTBYTES} bytes")
        if len(secret_key) != KYBER768_SECRETKEYBYTES:
            raise ValueError(f"Secret key must be {KYBER768_SECRETKEYBYTES} bytes")
        
        ss = (ctypes.c_uint8 * KYBER768_BYTES)()
        ct = (ctypes.c_uint8 * KYBER768_CIPHERTEXTBYTES)(*ciphertext)
        sk = (ctypes.c_uint8 * KYBER768_SECRETKEYBYTES)(*secret_key)
        
        result = self.lib.pqcrystals_kyber768_ref_dec(ss, ct, sk)
        if result != 0:
            raise RuntimeError(f"Kyber768 decapsulation failed with code {result}")
        
        return bytes(ss)