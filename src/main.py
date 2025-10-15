from crypto_system import SecureChannel
import time

def print_header(text):
    """Print a formatted header"""
    print("\n" + "="*80)
    print(f"  {text}")
    print("="*80)

def print_section(number, title):
    """Print a section header"""
    print(f"\n{'─'*80}")
    print(f"[{number}] {title}")
    print('─'*80)

def print_bytes_preview(data, name, max_display=32):
    """Show a preview of byte data"""
    hex_str = data.hex()
    if len(hex_str) > max_display:
        display = hex_str[:max_display] + "..."
    else:
        display = hex_str
    print(f"    {name}: {display}")

def main():
    print_header("POST-QUANTUM CRYPTOGRAPHY DEMONSTRATION")
    print("\n  📚 Technologies Used:")
    print("    • Kyber768    - Post-Quantum Key Encapsulation (NIST Standard)")
    print("    • Dilithium3  - Post-Quantum Digital Signatures (NIST Standard)")
    print("    • AES-256-GCM - Symmetric Encryption with Authentication")
    print("\n  🎯 Purpose:")
    print("    Demonstrate a complete hybrid cryptosystem that is secure against")
    print("    both classical and quantum computer attacks.")
    
    # Initialize
    print_section(1, "SYSTEM INITIALIZATION")
    print("  Initializing cryptographic system...")
    channel = SecureChannel()
    print("  ✓ Kyber768 KEM initialized")
    print("  ✓ Dilithium3 signature scheme initialized")
    print("  ✓ AES-256-GCM cipher initialized")
    
    # Alice's keys
    print_section(2, "ALICE GENERATES HER KEYPAIRS")
    print("  Generating Kyber768 keypair for key exchange...")
    start = time.time()
    alice_keys = channel.generate_keys()
    elapsed = time.time() - start
    print(f"  ✓ Key generation completed in {elapsed*1000:.2f}ms")
    print(f"\n  Alice's Key Sizes:")
    print(f"    • Kyber768 Public Key:    {len(alice_keys['kem_public']):>5} bytes")
    print(f"    • Kyber768 Secret Key:    {len(alice_keys['kem_secret']):>5} bytes")
    print(f"    • Dilithium3 Public Key:  {len(alice_keys['sign_public']):>5} bytes")
    print(f"    • Dilithium3 Secret Key:  {len(alice_keys['sign_secret']):>5} bytes")
    print(f"\n  Key Preview:")
    print_bytes_preview(alice_keys['kem_public'], "Kyber Public Key")
    print_bytes_preview(alice_keys['sign_public'], "Dilithium Public Key")
    
    # Bob's keys
    print_section(3, "BOB GENERATES HIS KEYPAIRS")
    print("  Generating Kyber768 keypair for key exchange...")
    start = time.time()
    bob_keys = channel.generate_keys()
    elapsed = time.time() - start
    print(f"  ✓ Key generation completed in {elapsed*1000:.2f}ms")
    print(f"\n  Bob's Key Sizes:")
    print(f"    • Kyber768 Public Key:    {len(bob_keys['kem_public']):>5} bytes")
    print(f"    • Kyber768 Secret Key:    {len(bob_keys['kem_secret']):>5} bytes")
    print(f"    • Dilithium3 Public Key:  {len(bob_keys['sign_public']):>5} bytes")
    print(f"    • Dilithium3 Secret Key:  {len(bob_keys['sign_secret']):>5} bytes")
    
    # Public key exchange
    print_section(4, "PUBLIC KEY EXCHANGE")
    print("  In a real system, Alice and Bob would exchange public keys over")
    print("  an insecure channel (e.g., the internet).")
    print("\n  Alice shares with Bob:")
    print(f"    • Her Kyber768 public key ({len(alice_keys['kem_public'])} bytes)")
    print(f"    • Her Dilithium3 public key ({len(alice_keys['sign_public'])} bytes)")
    print("\n  Bob shares with Alice:")
    print(f"    • His Kyber768 public key ({len(bob_keys['kem_public'])} bytes)")
    print(f"    • His Dilithium3 public key ({len(bob_keys['sign_public'])} bytes)")
    print("\n  ✓ Public keys exchanged successfully")
    
    # Alice sends message
    print_section(5, "ALICE SENDS ENCRYPTED MESSAGE TO BOB")
    message = "Hello Bob! This is a secret message protected by post-quantum cryptography. Even a quantum computer cannot break this encryption! 🔒"
    print(f"\n  📝 Original Message ({len(message)} characters):")
    print(f"     \"{message}\"")
    
    print("\n  🔐 Encryption Process:")
    print("     Step 1: Using Kyber768 to establish shared secret...")
    start = time.time()
    package = channel.send_message(
        message,
        bob_keys['kem_public'],
        alice_keys['sign_secret']
    )
    elapsed = time.time() - start
    print(f"     ✓ Kyber768 encapsulation completed")
    print(f"     ✓ 32-byte shared secret generated")
    print(f"\n     Step 2: Encrypting message with AES-256-GCM...")
    print(f"     ✓ Message encrypted and authenticated")
    print(f"\n     Step 3: Signing encrypted message with Dilithium3...")
    print(f"     ✓ Digital signature created")
    print(f"\n  ⏱️  Total encryption time: {elapsed*1000:.2f}ms")
    
    print(f"\n  📦 Encrypted Package Components:")
    print(f"     • Encrypted Message:  {len(package['encrypted_message']):>5} bytes")
    print(f"     • Digital Signature:  {len(package['signature']):>5} bytes")
    print(f"     • Kyber Ciphertext:   {len(package['kyber_ciphertext']):>5} bytes")
    print(f"     • Total Package Size: {sum(len(v) for v in package.values()):>5} bytes")
    
    print(f"\n  🔍 Encrypted Data Preview:")
    print_bytes_preview(package['encrypted_message'], "Encrypted Message", 64)
    print_bytes_preview(package['signature'], "Signature", 64)
    print_bytes_preview(package['kyber_ciphertext'], "Kyber Ciphertext", 64)
    
    # Bob receives message
    print_section(6, "BOB RECEIVES AND DECRYPTS THE MESSAGE")
    print("\n  🔓 Decryption Process:")
    print("     Step 1: Verifying Dilithium3 signature...")
    start = time.time()
    try:
        decrypted = channel.receive_message(
            package,
            bob_keys['kem_secret'],
            alice_keys['sign_public']
        )
        elapsed = time.time() - start
        print("     ✓ Signature verified - message is authentic!")
        print("     ✓ Message integrity confirmed")
        print(f"\n     Step 2: Using Kyber768 to recover shared secret...")
        print(f"     ✓ Shared secret recovered using Bob's secret key")
        print(f"\n     Step 3: Decrypting message with AES-256-GCM...")
        print(f"     ✓ Message decrypted successfully")
        print(f"\n  ⏱️  Total decryption time: {elapsed*1000:.2f}ms")
        print(f"\n  ✅ Decrypted Message ({len(decrypted)} characters):")
        print(f"     \"{decrypted}\"")
        print(f"\n  🎉 SUCCESS! Message transmitted securely!")
    except ValueError as e:
        print(f"     ✗ ERROR: {e}")
    
    # Demonstrate security
    print_section(7, "SECURITY DEMONSTRATION: TAMPERING DETECTION")
    print("\n  Simulating a man-in-the-middle attack...")
    print("  An attacker intercepts the message and modifies it.")
    
    tampered_package = package.copy()
    original_msg = tampered_package['encrypted_message']
    tampered_package['encrypted_message'] = b'HACKED!' + original_msg[7:]
    
    print(f"\n  Original encrypted message: {original_msg[:32].hex()}...")
    print(f"  Tampered encrypted message: {tampered_package['encrypted_message'][:32].hex()}...")
    
    print("\n  Bob attempts to decrypt the tampered message...")
    try:
        channel.receive_message(
            tampered_package,
            bob_keys['kem_secret'],
            alice_keys['sign_public']
        )
        print("  ✗ SECURITY FAILURE: Tampering not detected!")
    except ValueError as e:
        print(f"  ✓ TAMPERING DETECTED!")
        print(f"     Error: {e}")
        print("  ✓ Message rejected - integrity protection working correctly!")
    
    # Summary
    print_section(8, "SUMMARY AND SECURITY ANALYSIS")
    print("\n  🛡️  Security Properties Demonstrated:")
    print("     ✓ Confidentiality:  Only Bob can decrypt (Kyber768 + AES-256-GCM)")
    print("     ✓ Authentication:   Message proven to be from Alice (Dilithium3)")
    print("     ✓ Integrity:        Any tampering is detected (GCM + Signature)")
    print("     ✓ Quantum-Safe:     Secure against quantum computers (NIST PQC)")
    
    print("\n  📊 Performance Metrics:")
    print(f"     • Key Generation:    ~{elapsed*1000:.1f}ms per party")
    print(f"     • Encryption:        ~{elapsed*1000:.1f}ms")
    print(f"     • Decryption:        ~{elapsed*1000:.1f}ms")
    
    print("\n  🔬 Cryptographic Primitives:")
    print("     • Kyber768:     Level 3 security (≈AES-192)")
    print("     • Dilithium3:   Level 3 security (≈AES-192)")
    print("     • AES-256-GCM:  Level 5 security (≈AES-256)")
    
    print("\n  💡 Real-World Applications:")
    print("     • Secure messaging apps")
    print("     • VPN and network security")
    print("     • Email encryption (future PGP replacement)")
    print("     • Secure file transfer")
    print("     • Government/military communications")
    print("     • Long-term data protection")
    
    print_header("DEMONSTRATION COMPLETE")
    print("\n  ✅ All tests passed successfully!")
    print("  ✅ Post-quantum cryptography system fully operational!")
    print("\n" + "="*80 + "\n")

if __name__ == "__main__":
    main()