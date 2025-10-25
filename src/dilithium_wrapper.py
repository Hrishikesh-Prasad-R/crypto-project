import ctypes
from pathlib import Path
import platform

# Constants for Dilithium3
DILITHIUM3_PUBLICKEYBYTES = 1952
DILITHIUM3_SECRETKEYBYTES = 4032
DILITHIUM3_BYTES = 3309  # Max signature size

class Dilithium3:
    def __init__(self):
        system = platform.system()
        base_dir = Path(__file__).parent  # directory of this wrapper file

        if system == "Windows":
            lib_path = base_dir / "libpqcrystals_dilithium3_ref.dll"
        elif system == "Linux":
            lib_path = base_dir / "libpqcrystals_dilithium3_ref.so"
        else:
            raise RuntimeError(f"Unsupported OS: {system}")

        if not lib_path.exists():
            raise FileNotFoundError(f"Library not found: {lib_path}")

        # Load the shared library
        self.lib = ctypes.CDLL(str(lib_path))
        
        # Define function signatures
        # int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk)
        self.lib.pqcrystals_dilithium3_ref_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.lib.pqcrystals_dilithium3_ref_keypair.restype = ctypes.c_int
        
        # int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
        #                                         const uint8_t *m, size_t mlen,
        #                                         const uint8_t *ctx, size_t ctxlen,
        #                                         const uint8_t *sk)
        self.lib.pqcrystals_dilithium3_ref_signature.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.lib.pqcrystals_dilithium3_ref_signature.restype = ctypes.c_int
        
        # int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
        #                                      const uint8_t *m, size_t mlen,
        #                                      const uint8_t *ctx, size_t ctxlen,
        #                                      const uint8_t *pk)
        self.lib.pqcrystals_dilithium3_ref_verify.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.lib.pqcrystals_dilithium3_ref_verify.restype = ctypes.c_int
    
    def keypair(self):
        """Generate a Dilithium3 keypair"""
        pk = (ctypes.c_uint8 * DILITHIUM3_PUBLICKEYBYTES)()
        sk = (ctypes.c_uint8 * DILITHIUM3_SECRETKEYBYTES)()
        
        result = self.lib.pqcrystals_dilithium3_ref_keypair(pk, sk)
        if result != 0:
            raise RuntimeError(f"Dilithium3 keypair generation failed with code {result}")
        
        return bytes(pk), bytes(sk)
    
    def sign(self, message, secret_key, context=b""):
        """Sign a message"""
        if len(secret_key) != DILITHIUM3_SECRETKEYBYTES:
            raise ValueError(f"Secret key must be {DILITHIUM3_SECRETKEYBYTES} bytes")
        
        sig = (ctypes.c_uint8 * DILITHIUM3_BYTES)()
        siglen = ctypes.c_size_t()
        msg = (ctypes.c_uint8 * len(message))(*message)
        ctx = (ctypes.c_uint8 * len(context))(*context) if context else None
        sk = (ctypes.c_uint8 * DILITHIUM3_SECRETKEYBYTES)(*secret_key)
        
        result = self.lib.pqcrystals_dilithium3_ref_signature(
            sig, ctypes.byref(siglen),
            msg, len(message),
            ctx, len(context),
            sk
        )
        
        if result != 0:
            raise RuntimeError(f"Dilithium3 signing failed with code {result}")
        
        return bytes(sig[:siglen.value])
    
    def verify(self, signature, message, public_key, context=b""):
        """Verify a signature"""
        if len(public_key) != DILITHIUM3_PUBLICKEYBYTES:
            raise ValueError(f"Public key must be {DILITHIUM3_PUBLICKEYBYTES} bytes")
        
        sig = (ctypes.c_uint8 * len(signature))(*signature)
        msg = (ctypes.c_uint8 * len(message))(*message)
        ctx = (ctypes.c_uint8 * len(context))(*context) if context else None
        pk = (ctypes.c_uint8 * DILITHIUM3_PUBLICKEYBYTES)(*public_key)
        
        result = self.lib.pqcrystals_dilithium3_ref_verify(
            sig, len(signature),
            msg, len(message),
            ctx, len(context),
            pk
        )
        
        return result == 0  # 0 means valid signature