"""
Attack Demonstration Module
Shows various attacks and how the system defends against them
"""

from crypto_system import SecureChannel
import hashlib
import time
from colorama import init, Fore, Style
init(autoreset=True)

class AttackSimulator:
    def __init__(self):
        self.channel = SecureChannel()
    
    def print_attack_header(self, attack_name):
        print("\n" + "="*80)
        print(f"{Fore.RED}🚨 ATTACK SIMULATION: {attack_name}")
        print("="*80)
    
    def print_defense(self, message):
        print(f"{Fore.GREEN}🛡️  DEFENSE: {message}")
    
    def print_attacker(self, message):
        print(f"{Fore.RED}👹 ATTACKER: {message}")
    
    def print_status(self, message):
        print(f"{Fore.CYAN}ℹ️  {message}")
    
    def man_in_the_middle_attack(self):
        """Demonstrate MITM attack and how signatures prevent it"""
        self.print_attack_header("MAN-IN-THE-MIDDLE (MITM) ATTACK")
        
        # Setup
        print("\n📋 SCENARIO SETUP:")
        alice_keys = self.channel.generate_keys()
        bob_keys = self.channel.generate_keys()
        eve_keys = self.channel.generate_keys()  # Attacker
        
        print("  ✓ Alice generates her keypairs")
        print("  ✓ Bob generates his keypairs")
        print(f"{Fore.RED}  ✓ Eve (attacker) generates her keypairs")
        
        # Normal communication
        print("\n" + "─"*80)
        print("PHASE 1: NORMAL SECURE COMMUNICATION")
        print("─"*80)
        
        message = "Bob, let's meet at the secret location at midnight."
        print(f"\n💬 Alice wants to send: \"{message}\"")
        
        package = self.channel.send_message(
            message,
            bob_keys['kem_public'],
            alice_keys['sign_secret']
        )
        
        print("  ✓ Alice encrypts message to Bob")
        print("  ✓ Alice signs message with her secret key")
        print("\n📡 Message transmitted over insecure channel...")
        
        decrypted = self.channel.receive_message(
            package,
            bob_keys['kem_secret'],
            alice_keys['sign_public']
        )
        
        print(f"{Fore.GREEN}  ✓ Bob verifies signature (authentic!)")
        print(f"{Fore.GREEN}  ✓ Bob decrypts message")
        print(f"{Fore.GREEN}  ✓ Bob reads: \"{decrypted}\"")
        
        # MITM Attack Attempt 1: Message Modification
        print("\n" + "─"*80)
        print("PHASE 2: MITM ATTACK - MESSAGE TAMPERING")
        print("─"*80)
        
        self.print_attacker("Intercepting Alice's message to Bob...")
        self.print_attacker("Attempting to modify the encrypted message...")
        
        # Eve modifies the encrypted message
        tampered_package = package.copy()
        original = tampered_package['encrypted_message']
        tampered_package['encrypted_message'] = b'HACKED' + original[6:]
        
        print(f"\n{Fore.RED}📝 Original encrypted: {original[:32].hex()}...")
        print(f"{Fore.RED}📝 Modified encrypted: {tampered_package['encrypted_message'][:32].hex()}...")
        
        self.print_attacker("Forwarding tampered message to Bob...")
        
        print(f"\n{Fore.YELLOW}Bob attempts to decrypt...")
        try:
            self.channel.receive_message(
                tampered_package,
                bob_keys['kem_secret'],
                alice_keys['sign_public']
            )
            print(f"{Fore.RED}❌ SECURITY FAILURE!")
        except ValueError as e:
            self.print_defense("TAMPERING DETECTED!")
            print(f"  Reason: {e}")
            print(f"{Fore.GREEN}  ✓ Message rejected - Bob knows it's been tampered with")
        
        # MITM Attack Attempt 2: Signature Forgery
        print("\n" + "─"*80)
        print("PHASE 3: MITM ATTACK - SIGNATURE FORGERY")
        print("─"*80)
        
        self.print_attacker("Attempting to forge Alice's signature...")
        
        fake_message = "Bob, send $10,000 to Eve's account immediately!"
        print(f"\n{Fore.RED}💬 Eve's fake message: \"{fake_message}\"")
        
        # Eve tries to create a message and sign it with her own key
        fake_package = self.channel.send_message(
            fake_message,
            bob_keys['kem_public'],
            eve_keys['sign_secret']  # Eve signs with her own key
        )
        
        self.print_attacker("Sending forged message to Bob...")
        
        print(f"\n{Fore.YELLOW}Bob attempts to verify with Alice's public key...")
        try:
            self.channel.receive_message(
                fake_package,
                bob_keys['kem_secret'],
                alice_keys['sign_public']  # Verifying with Alice's public key
            )
            print(f"{Fore.RED}❌ SECURITY FAILURE!")
        except ValueError as e:
            self.print_defense("FORGED SIGNATURE DETECTED!")
            print(f"  Reason: {e}")
            print(f"{Fore.GREEN}  ✓ Bob knows this isn't from Alice")
        
        # MITM Attack Attempt 3: Key Substitution
        print("\n" + "─"*80)
        print("PHASE 4: MITM ATTACK - PUBLIC KEY SUBSTITUTION")
        print("─"*80)
        
        self.print_attacker("Intercepting public key exchange...")
        self.print_attacker("Replacing Alice's public key with Eve's public key...")
        
        print(f"\n{Fore.RED}Scenario: Eve intercepts Alice's public key and replaces it")
        print(f"{Fore.YELLOW}⚠️  This attack succeeds if there's no out-of-band verification!")
        
        # Eve creates a message pretending to be Alice
        evil_package = self.channel.send_message(
            "Hi Bob, this is totally from Alice! ;)",
            bob_keys['kem_public'],
            eve_keys['sign_secret']
        )
        
        # Bob verifies with Eve's key (thinking it's Alice's)
        evil_decrypted = self.channel.receive_message(
            evil_package,
            bob_keys['kem_secret'],
            eve_keys['sign_public']  # Bob uses wrong public key!
        )
        
        print(f"{Fore.RED}❌ Attack succeeds: \"{evil_decrypted}\"")
        print(f"\n{Fore.YELLOW}💡 LESSON: Public key distribution needs additional authentication!")
        print(f"{Fore.CYAN}   Solutions:")
        print(f"{Fore.CYAN}   • Certificate Authorities (PKI)")
        print(f"{Fore.CYAN}   • Web of Trust")
        print(f"{Fore.CYAN}   • Out-of-band verification (phone call, in-person)")
        print(f"{Fore.CYAN}   • Key fingerprint comparison")
        
        # Summary
        print("\n" + "="*80)
        print(f"{Fore.GREEN}MITM DEFENSE SUMMARY")
        print("="*80)
        print(f"{Fore.GREEN}✓ Message tampering: BLOCKED by digital signatures")
        print(f"{Fore.GREEN}✓ Signature forgery: IMPOSSIBLE without private key")
        print(f"{Fore.YELLOW}⚠ Key substitution: Requires additional PKI layer")
    
    def replay_attack(self):
        """Demonstrate replay attack with timestamps"""
        self.print_attack_header("REPLAY ATTACK")
        
        print("\n📋 SCENARIO:")
        print("  Alice sends 'Transfer $100 to Bob' message")
        print("  Eve captures this valid message")
        print("  Eve replays it multiple times to drain Alice's account")
        
        alice_keys = self.channel.generate_keys()
        bob_keys = self.channel.generate_keys()
        
        # Original message
        print("\n" + "─"*80)
        print("ORIGINAL TRANSACTION")
        print("─"*80)
        
        message = "TRANSACTION: Transfer $100 from Alice to Bob"
        timestamp1 = int(time.time())
        timestamped_msg = f"{message}|TIMESTAMP:{timestamp1}"
        
        print(f"💬 Message: {message}")
        print(f"⏰ Timestamp: {timestamp1}")
        
        package = self.channel.send_message(
            timestamped_msg,
            bob_keys['kem_public'],
            alice_keys['sign_secret']
        )
        
        decrypted = self.channel.receive_message(
            package,
            bob_keys['kem_secret'],
            alice_keys['sign_public']
        )
        
        print(f"{Fore.GREEN}✓ Transaction processed successfully")
        
        # Replay attempt
        print("\n" + "─"*80)
        print("REPLAY ATTACK ATTEMPT")
        print("─"*80)
        
        time.sleep(2)  # Simulate time passing
        
        self.print_attacker("Captured the original encrypted message")
        self.print_attacker("Replaying the same message 5 seconds later...")
        
        # Attacker replays the same package
        print(f"\n{Fore.YELLOW}Bob receives the replayed message...")
        
        replayed_msg = self.channel.receive_message(
            package,
            bob_keys['kem_secret'],
            alice_keys['sign_public']
        )
        
        # Extract timestamp
        msg_content, timestamp_part = replayed_msg.rsplit('|TIMESTAMP:', 1)
        old_timestamp = int(timestamp_part)
        current_time = int(time.time())
        age = current_time - old_timestamp
        
        print(f"📝 Decrypted message: {msg_content}")
        print(f"⏰ Message timestamp: {old_timestamp}")
        print(f"⏰ Current time: {current_time}")
        print(f"⏱️  Message age: {age} seconds")
        
        if age > 3:  # 3 second threshold
            self.print_defense("REPLAY ATTACK DETECTED!")
            print(f"{Fore.GREEN}  Message is too old (>{age}s), rejecting...")
            print(f"{Fore.GREEN}  ✓ Transaction blocked")
        else:
            print(f"{Fore.RED}  ❌ Message accepted (within time window)")
        
        print("\n" + "="*80)
        print(f"{Fore.GREEN}REPLAY ATTACK DEFENSE")
        print("="*80)
        print(f"{Fore.CYAN}• Use timestamps in signed messages")
        print(f"{Fore.CYAN}• Reject messages older than threshold")
        print(f"{Fore.CYAN}• Use nonces (number used once)")
        print(f"{Fore.CYAN}• Keep database of processed message IDs")
    
    def brute_force_analysis(self):
        """Analyze brute force attack complexity"""
        self.print_attack_header("BRUTE FORCE ATTACK ANALYSIS")
        
        print("\n" + "─"*80)
        print("CLASSICAL COMPUTER ATTACKS")
        print("─"*80)
        
        # Kyber768 security
        kyber_bits = 192  # NIST Level 3
        kyber_operations = 2 ** kyber_bits
        
        print(f"\n🔐 KYBER768 Security:")
        print(f"   Security Level: {kyber_bits} bits (NIST Level 3)")
        print(f"   Operations needed: 2^{kyber_bits} = {kyber_operations:.2e}")
        
        # Assume 1 trillion operations per second
        ops_per_second = 1e12
        seconds = kyber_operations / ops_per_second
        years = seconds / (365.25 * 24 * 3600)
        
        print(f"\n⏱️  Attack Time (1 trillion ops/second):")
        print(f"   {seconds:.2e} seconds")
        print(f"   {years:.2e} years")
        print(f"   {Fore.GREEN}Age of universe: ~1.38×10^10 years")
        
        if years > 1e10:
            print(f"   {Fore.GREEN}✓ SECURE: Attack takes longer than age of universe!")
        
        # Dilithium3 security
        print(f"\n🔐 DILITHIUM3 Security:")
        print(f"   Security Level: {kyber_bits} bits (NIST Level 3)")
        print(f"   Same security analysis as Kyber768")
        
        # Compare with RSA
        print("\n" + "─"*80)
        print("COMPARISON WITH RSA-2048")
        print("─"*80)
        
        print(f"\n📊 RSA-2048:")
        print(f"   Equivalent security: ~112 bits (classical)")
        rsa_ops = 2 ** 112
        rsa_years = (rsa_ops / ops_per_second) / (365.25 * 24 * 3600)
        print(f"   Attack time: ~{rsa_years:.2e} years")
        
        print(f"\n📊 Kyber768:")
        print(f"   Equivalent security: ~192 bits (classical)")
        print(f"   Attack time: ~{years:.2e} years")
        
        improvement = years / rsa_years
        print(f"\n{Fore.GREEN}Kyber768 is ~{improvement:.2e}x more secure than RSA-2048!")
        
        # Quantum attacks
        print("\n" + "─"*80)
        print("QUANTUM COMPUTER ATTACKS")
        print("─"*80)
        
        print(f"\n⚛️  Shor's Algorithm (Quantum Attack on RSA):")
        print(f"   RSA-2048 security: BROKEN")
        print(f"   Estimated qubits needed: ~4000-8000")
        print(f"   Time complexity: Polynomial O(n³)")
        print(f"   {Fore.RED}❌ RSA is vulnerable to quantum computers!")
        
        print(f"\n⚛️  Grover's Algorithm (Quantum Attack on Kyber):")
        print(f"   Kyber768 security: {kyber_bits} bits → {kyber_bits//2} bits (quantum)")
        print(f"   Still {kyber_bits//2} bits of security!")
        quantum_ops = 2 ** (kyber_bits // 2)
        
        # Quantum computer estimate (much slower than classical)
        quantum_ops_per_sec = 1e6  # Estimated
        quantum_years = (quantum_ops / quantum_ops_per_sec) / (365.25 * 24 * 3600)
        
        print(f"   Quantum attack time: ~{quantum_years:.2e} years")
        print(f"   {Fore.GREEN}✓ Still secure against quantum computers!")
        
        print("\n" + "="*80)
        print(f"{Fore.GREEN}BRUTE FORCE RESISTANCE SUMMARY")
        print("="*80)
        print(f"{Fore.GREEN}✓ Classical computers: Impossible to break")
        print(f"{Fore.GREEN}✓ Quantum computers: Still secure (96-bit quantum security)")
        print(f"{Fore.RED}✗ RSA-2048: Broken by quantum computers")
        print(f"{Fore.CYAN}💡 Post-Quantum Cryptography is essential for long-term security!")

def main():
    print(f"\n{Fore.CYAN}" + "="*80)
    print(f"{Fore.CYAN}CRYPTOGRAPHIC ATTACK DEMONSTRATION SUITE")
    print(f"{Fore.CYAN}Testing Kyber768 + Dilithium3 Security")
    print(f"{Fore.CYAN}" + "="*80)
    
    simulator = AttackSimulator()
    
    # Run all attacks
    simulator.man_in_the_middle_attack()
    input(f"\n{Fore.YELLOW}Press Enter to continue to next attack...")
    
    simulator.replay_attack()
    input(f"\n{Fore.YELLOW}Press Enter to continue to security analysis...")
    
    simulator.brute_force_analysis()
    
    print(f"\n{Fore.GREEN}" + "="*80)
    print(f"{Fore.GREEN}ALL ATTACK DEMONSTRATIONS COMPLETE")
    print(f"{Fore.GREEN}" + "="*80 + "\n")

if __name__ == "__main__":
    main()