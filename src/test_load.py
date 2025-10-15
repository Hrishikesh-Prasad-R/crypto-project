import ctypes
from pathlib import Path

print("Attempting to load DLL...")
dll_path = Path("kyber/ref/lib/libpqcrystals_kyber768_ref.dll")
print(f"DLL path: {dll_path.absolute()}")
print(f"DLL exists: {dll_path.exists()}")

try:
    lib = ctypes.CDLL(str(dll_path.absolute()))
    print("✓ DLL loaded successfully!")
except Exception as e:
    print(f"✗ Failed to load DLL: {e}")
    exit(1)

print("\nAttempting to find keypair function...")
try:
    keypair_func = lib.pqcrystals_kyber768_ref_keypair
    print("✓ Found keypair function!")
except Exception as e:
    print(f"✗ Failed to find function: {e}")
    exit(1)

print("\nSetting up function signature...")
keypair_func.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8)
]
keypair_func.restype = ctypes.c_int
print("✓ Function signature set!")

print("\nAllocating memory...")
pk = (ctypes.c_uint8 * 1184)()
sk = (ctypes.c_uint8 * 2400)()
print("✓ Memory allocated!")

print("\nCalling keypair function...")
print("(This is where it might hang...)")
import time
start = time.time()
result = keypair_func(pk, sk)
end = time.time()

print(f"✓ Function returned in {end-start:.2f} seconds!")
print(f"  Return value: {result}")
print(f"  First byte of pk: {pk[0]}")