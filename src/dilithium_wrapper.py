import ctypes
from pathlib import Path
import platform
import os

# Constants for Dilithium3
DILITHIUM3_PUBLICKEYBYTES = 1952
DILITHIUM3_SECRETKEYBYTES = 4032
DILITHIUM3_BYTES = 3309  # Max signature size

class Dilithium3:
    def __init__(self):
        system = platform.system()
        base_dir = Path(__file__).parent.absolute()

        if system == "Windows":
            lib_name = "libpqcrystals_dilithium3_ref.dll"
        elif system == "Linux":
            lib_name = "libpqcrystals_dilithium3_ref.so"
        elif system == "Darwin":  # macOS
            lib_name = "libpqcrystals_dilithium3_ref.dylib"
        else:
            raise RuntimeError(f"Unsupported OS: {system}")

        lib_path = base_dir / lib_name  # FIXED: Properly join Path objects

        if not lib_path.exists():
            available_files = list(base_dir.glob("*"))
            error_msg = (
                f"Dilithium library not found!\n"
                f"Expected: {lib_path}\n"
                f"Base directory: {base_dir}\n"
                f"Platform: {system}\n"
                f"Available files: {available_files}\n"
                f"Current working directory: {os.getcwd()}"
            )
            raise FileNotFoundError(error_msg)

        # Load the shared library with better error handling
        try:
            self.lib = ctypes.CDLL(str(lib_path))
        except OSError as e:
            error_msg = (
                f"Failed to load Dilithium library from {lib_path}\n"
                f"Error: {str(e)}\n"
                f"Platform: {system}\n"
                f"Try installing required dependencies with: sudo apt-get install libgomp1"
            )
            raise OSError(error_msg) from e
        
        # Define function signatures - use ref for all platforms for compatibility
        keypair_func = "pqcrystals_dilithium3_ref_keypair"
        signature_func = "pqcrystals_dilithium3_ref_signature"
        verify_func = "pqcrystals_dilithium3_ref_verify"
        
        # int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk)
        self.keypair_func = getattr(self.lib, keypair_func)
        self.keypair_func.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.keypair_func.restype = ctypes.c_int
        
        # int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
        #                                         const uint8_t *m, size_t mlen,
        #                                         const uint8_t *ctx, size_t ctxlen,
        #                                         const uint8_t *sk)
        self.signature_func = getattr(self.lib, signature_func)
        self.signature_func.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.signature_func.restype = ctypes.c_int
        
        # int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
        #                                      const uint8_t *m, size_t mlen,
        #                                      const uint8_t *ctx, size_t ctxlen,
        #                                      const uint8_t *pk)
        self.verify_func = getattr(self.lib, verify_func)
        self.verify_func.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.verify_func.restype = ctypes.c_int
    
    def keypair(self):
        """Generate a Dilithium3 keypair"""
        pk = (ctypes.c_uint8 * DILITHIUM3_PUBLICKEYBYTES)()
        sk = (ctypes.c_uint8 * DILITHIUM3_SECRETKEYBYTES)()
        
        result = self.keypair_func(pk, sk)
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
        
        result = self.signature_func(
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
        
        result = self.verify_func(
            sig, len(signature),
            msg, len(message),
            ctx, len(context),
            pk
        )
        
        return result == 0  # 0 means valid signature