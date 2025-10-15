from crypto_system import SecureChannel

def main():
    print("=" * 70)
    print("POST-QUANTUM CRYPTOGRAPHY DEMO")
    print("Kyber768 (KEM) + Dilithium3 (Signatures) + AES-256-GCM")
    print("=" * 70)
    
    # Initialize the secure channel
    channel = SecureChannel()
    
    # Alice generates her keys
    print("\n[1] Alice generates her keypairs...")
    alice_keys = channel.generate_keys()
    print(f"    ✓ Kyber768 public key: {len(alice_keys['kem_public'])} bytes")
    print(f"    ✓ Dilithium3 public key: {len(alice_keys['sign_public'])} bytes")
    
    # Bob generates his keys
    print("\n[2] Bob generates his keypairs...")
    bob_keys = channel.generate_keys()
    print(f"    ✓ Kyber768 public key: {len(bob_keys['kem_public'])} bytes")
    print(f"    ✓ Dilithium3 public key: {len(bob_keys['sign_public'])} bytes")
    
    # Alice sends a message to Bob
    print("\n[3] Alice sends encrypted message to Bob...")
    message = "Hello Bob! This message is protected by post-quantum cryptography!"
    print(f"    Original message: '{message}'")
    
    package = channel.send_message(
        message,
        bob_keys['kem_public'],      # Encrypt to Bob's public key
        alice_keys['sign_secret']     # Sign with Alice's secret key
    )
    
    print(f"    ✓ Encrypted message: {len(package['encrypted_message'])} bytes")
    print(f"    ✓ Signature: {len(package['signature'])} bytes")
    print(f"    ✓ Kyber ciphertext: {len(package['kyber_ciphertext'])} bytes")
    
    # Bob receives and decrypts
    print("\n[4] Bob receives and verifies the message...")
    try:
        decrypted = channel.receive_message(
            package,
            bob_keys['kem_secret'],      # Decrypt with Bob's secret key
            alice_keys['sign_public']     # Verify with Alice's public key
        )
        print(f"    ✓ Signature verified!")
        print(f"    ✓ Decrypted message: '{decrypted}'")
    except ValueError as e:
        print(f"    ✗ Error: {e}")
    
    # Demonstrate tamper detection
    print("\n[5] Testing tamper detection...")
    print("    Modifying encrypted message...")
    tampered_package = package.copy()
    tampered_package['encrypted_message'] = b'tampered' + package['encrypted_message'][8:]
    
    try:
        channel.receive_message(
            tampered_package,
            bob_keys['kem_secret'],
            alice_keys['sign_public']
        )
        print("    ✗ Tamper detection failed!")
    except ValueError as e:
        print(f"    ✓ Tampering detected: {e}")
    
    print("\n" + "=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)

if __name__ == "__main__":
    main()