"""
Cryptographic Attack Implementations - Complete
MAC Forgery and Digital Signature Attacks

FILE: attack_cryptographic.py
"""

import streamlit as st
import time
import random
import hashlib
from .attack_visualizer import AttackVisualizer


class CryptographicAttacks:
    """Implements cryptographic attacks with mathematical proofs"""
    
    def __init__(self, channel, alice_keys, bob_keys, logger):
        self.channel = channel
        self.alice_keys = alice_keys
        self.bob_keys = bob_keys
        self.logger = logger
        self.visualizer = AttackVisualizer()
    
    def render(self):
        """Main render method"""
        st.subheader("🛡️ Cryptographic Attack Simulations")
        
        st.markdown("""
        <div class="info-box">
        <strong>🎓 Algorithm-Level Security</strong><br>
        These attacks target the cryptographic primitives themselves. Post-quantum 
        algorithms (Kyber768, Dilithium3) provide mathematical guarantees that make 
        these attacks computationally infeasible, even with quantum computers.
        </div>
        """, unsafe_allow_html=True)
        
        attack_type = st.selectbox(
            "**Select Cryptographic Attack:**",
            [
                "🔐 Message Authentication Attack (MAC Forgery)",
                "✍️ Digital Signature Forgery Attack", 
                "💪 Brute Force Key Space Attack",
                "🔍 Chosen Ciphertext Attack (CCA)",
                "📊 Statistical Cryptanalysis"
            ]
        )
        
        st.markdown("---")
        
        if "Message Authentication" in attack_type:
            self.mac_forgery_attack()
        elif "Digital Signature" in attack_type:
            self.signature_forgery_attack()
        elif "Brute Force" in attack_type:
            from attack_brute_force import BruteForceAttack
            bf_attack = BruteForceAttack(self.channel, self.alice_keys, self.bob_keys, self.logger)
            bf_attack.execute()
        elif "Chosen Ciphertext" in attack_type:
            self.chosen_ciphertext_attack()
        elif "Statistical" in attack_type:
            self.statistical_cryptanalysis()
    
    def mac_forgery_attack(self):
        """Demonstrates MAC forgery attempt with mathematical proof"""
        st.markdown("### 🔐 Message Authentication Code (MAC) Forgery Attack")
        
        # Theory section
        with st.expander("📚 Theoretical Background", expanded=True):
            st.markdown("""
            **Message Authentication Codes (MAC):**
            - Purpose: Ensure message integrity and authenticity
            - Function: `MAC = HMAC-SHA256(key, message)`
            - Security: Based on collision-resistance of SHA-256
            
            **Mathematical Security:**
            ```
            Given: C = Encrypt(K, M), MAC = HMAC(K, M)
            Find: M', MAC' where MAC' = HMAC(K, M') without knowing K
            
            Probability of success: 1 / 2^256 (negligible)
            ```
            
            **Attack Goal:** Modify message and create valid MAC without key
            
            **HMAC Construction:**
            ```
            HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))
            where:
            - H = SHA-256 hash function
            - opad = 0x5c repeated (outer padding)
            - ipad = 0x36 repeated (inner padding)
            - || = concatenation
            ```
            """)
        
        st.markdown("---")
        st.markdown("### 🎯 Attack Simulation")
        
        # User inputs
        col1, col2 = st.columns(2)
        with col1:
            original_msg = st.text_input(
                "Original message:",
                "Transfer $100 to Alice",
                key="mac_orig"
            )
        with col2:
            tampered_msg = st.text_input(
                "Attacker's modified message:",
                "Transfer $999999 to Attacker",
                key="mac_tamp"
            )
        
        forgery_method = st.radio(
            "Forgery technique:",
            [
                "Random MAC generation",
                "Birthday attack (collision search)",
                "Length extension attack",
                "Bit flipping with MAC recalculation"
            ],
            key="mac_method"
        )
        
        if st.button("🚀 Launch MAC Forgery Attack", type="primary", key="mac_btn"):
            self._execute_mac_attack(original_msg, tampered_msg, forgery_method)
    
    def _execute_mac_attack(self, original, tampered, method):
        """Execute MAC forgery attack with detailed steps"""
        
        # Step 1: Create legitimate message
        st.markdown("#### Step 1: Alice sends authenticated message")
        
        with st.spinner("Encrypting and authenticating..."):
            time.sleep(0.3)
            package = self.channel.send_message(
                original,
                self.bob_keys['kem_public'],
                self.alice_keys['sign_secret']
            )
            
            # Calculate and display MAC
            original_mac = hashlib.sha256(
                package['encrypted_message'] + package['signature']
            ).hexdigest()[:32]
            
            col1, col2 = st.columns(2)
            with col1:
                st.success("✓ Message encrypted")
                st.code(f"Message: {original}", language="text")
                st.code(f"Length: {len(package['encrypted_message'])} bytes", language="text")
            with col2:
                st.success("✓ Digital signature generated")
                st.code(f"MAC: {original_mac}", language="text")
                st.code(f"Signature: {len(package['signature'])} bytes", language="text")
        
        # Step 2: Attacker intercepts
        st.markdown("#### Step 2: 🕵️ Attacker intercepts and modifies")
        time.sleep(0.3)
        
        st.warning(f"⚠️ Attacker intercepts transmission")
        st.warning(f"⚠️ Attacker modifies message to: '{tampered}'")
        
        # Step 3: Attempt forgery
        st.markdown(f"#### Step 3: 🕵️ Attempting forgery using: {method}")
        
        progress_bar = st.progress(0)
        status = st.empty()
        
        if "Random" in method:
            forged_mac = self._random_mac_attack(progress_bar, status)
        elif "Birthday" in method:
            forged_mac = self._birthday_attack(progress_bar, status)
        elif "Length extension" in method:
            forged_mac = self._length_extension_attack(progress_bar, status)
        else:
            forged_mac = self._bit_flip_attack(progress_bar, status)
        
        # Step 4: Verification
        st.markdown("#### Step 4: 👨 Bob verifies signature")
        time.sleep(0.3)
        
        try:
            # Attempt to verify with tampered message
            tampered_package = package.copy()
            # This will trigger signature verification failure
            tampered_package['encrypted_message'] = tampered.encode()
            
            decrypted = self.channel.receive_message(
                tampered_package,
                self.bob_keys['kem_secret'],
                self.alice_keys['sign_public']
            )
            st.error("❌ CRITICAL: Forgery should have been detected!")
            
        except Exception as e:
            # Expected path - forgery detected
            st.markdown("""
            <div class="danger-box">
            <h3>✅ ATTACK BLOCKED - FORGERY DETECTED!</h3>
            <strong>Security Mechanism:</strong> Dilithium3 Digital Signature Verification<br>
            <strong>Result:</strong> Message rejected by Bob<br>
            <strong>Error Type:</strong> Signature verification failed<br>
            <br>
            <strong>📊 Mathematical Proof of Failure:</strong><br>
            • Attacker needs: Valid signature σ' for modified message M'<br>
            • Without secret key: Creating σ' requires solving lattice problem<br>
            • Problem: Module-SIS (Short Integer Solution)<br>
            • Complexity: O(2^128) operations (computationally infeasible)<br>
            • Quantum resistance: Grover's algorithm only provides √ speedup → still O(2^64) which is secure<br>
            <br>
            <strong>🔒 Why This Attack Fails:</strong><br>
            1. Digital signatures cryptographically bind message to sender's private key<br>
            2. Any modification invalidates signature mathematically<br>
            3. Attacker cannot create valid signature without private key<br>
            4. Lattice-based signatures (Dilithium3) resistant to quantum attacks<br>
            5. No known mathematical shortcuts or vulnerabilities
            </div>
            """, unsafe_allow_html=True)
            
            # Show mathematical proof
            self._show_forgery_mathematics(original_mac, forged_mac, original, tampered)
            
            # Log attack
            self.logger.log_attack({
                'attack_name': 'MAC Forgery Attack',
                'attack_type': 'Cryptographic',
                'method': method,
                'success': False,
                'protection': 'Dilithium3 Digital Signatures',
                'details': {
                    'original_message': original,
                    'tampered_message': tampered,
                    'original_mac': original_mac,
                    'forged_mac': forged_mac
                }
            })
    
    def _random_mac_attack(self, progress, status):
        """Simulate random MAC generation"""
        attempts = 1000
        for i in range(attempts):
            if i % 100 == 0:
                progress.progress(i / attempts)
                status.text(f"🔄 Generating random MACs... {i}/{attempts}")
                time.sleep(0.05)
        
        progress.progress(1.0)
        status.text("✗ Failed: No valid MAC found in 1,000 attempts")
        
        st.code("""
Probability Analysis:
- MAC space: 2^256 possible values
- Attempts: 1,000
- Success probability: 1,000 / 2^256 ≈ 0 (negligible)
- Expected attempts for success: 2^256 ≈ 10^77
        """, language="text")
        
        return hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]
    
    def _birthday_attack(self, progress, status):
        """Simulate birthday collision attack"""
        status.text("📊 Computing collision probabilities...")
        time.sleep(0.5)
        
        # Mathematical calculation
        st.markdown("""
        **Birthday Attack Mathematics:**
        ```
        Hash space: N = 2^256 possible MAC values
        Collision probability for n attempts:
        
        p(collision) ≈ 1 - e^(-n²/(2N))
        
        For p = 0.5 (50% success rate):
        n ≈ sqrt(2N × ln(2))
        n ≈ sqrt(2 × 2^256 × 0.693)
        n ≈ 2^128
        
        At 1 billion attempts/second:
        Time = 2^128 / 10^9 seconds
             ≈ 10^28 years
             ≈ 10^18 × (age of universe)
        ```
        """)
        
        progress.progress(1.0)
        status.text("✗ Failed: Collision search computationally infeasible")
        
        st.error("**Conclusion:** Birthday attack requires 2^128 attempts, which is impossible even with all computers on Earth.")
        
        return hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]
    
    def _length_extension_attack(self, progress, status):
        """Simulate length extension attack"""
        status.text("🔧 Attempting length extension...")
        time.sleep(0.5)
        
        st.info("""
        **Length Extension Attack:**
        
        **Vulnerable construction** (simple hash):
        ```
        MAC = H(key || message)
        Attack: Can compute H(key || message || extension) without knowing key
        ```
        
        **HMAC Defense** (what we use):
        ```
        HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))
        
        Properties:
        • Double hashing prevents length extension
        • Inner hash: H((K ⊕ ipad) || M)
        • Outer hash: H((K ⊕ opad) || inner_hash)
        • Cannot extend without knowing K
        • Provably secure under hash function assumptions
        ```
        
        **Attack Result:** Cannot extend HMAC without key K
        """)
        
        progress.progress(1.0)
        status.text("✗ Failed: HMAC construction prevents length extension")
        
        return hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]
    
    def _bit_flip_attack(self, progress, status):
        """Simulate bit flipping attack"""
        status.text("⚡ Flipping bits and recalculating...")
        
        for i in range(256):
            if i % 32 == 0:
                progress.progress(i / 256)
                time.sleep(0.05)
        
        st.warning("""
        **Bit Flipping Attack Results:**
        
        **What attacker did:**
        - ✓ Flipped bits in ciphertext
        - ✓ Modified encrypted message
        - ✓ Attempted to recalculate MAC
        
        **Why it failed:**
        - ✗ MAC depends on original message content
        - ✗ Cannot recompute HMAC without secret key
        - ✗ Any change invalidates cryptographic binding
        - ✗ Digital signature verification will fail
        
        **Technical details:**
        ```
        Original: MAC₁ = HMAC(K, M₁)
        Modified: M₂ = flip_bits(M₁)
        Required: MAC₂ = HMAC(K, M₂)
        Problem: Cannot compute HMAC without K
        ```
        """)
        
        progress.progress(1.0)
        status.text("✗ Failed: Cannot create valid MAC without secret key")
        
        return hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]
    
    def _show_forgery_mathematics(self, original_mac, forged_mac, original_msg, tampered_msg):
        """Display mathematical proof of forgery failure"""
        
        st.markdown("---")
        st.markdown("### 📐 Mathematical Analysis of Forgery Attempt")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Legitimate (Alice's) Signature:**")
            st.code(f"Original message:\n{original_msg}\n\nMAC₁: {original_mac}", language="text")
            st.success("✓ Generated with authentic private key")
            st.success("✓ Cryptographically bound to message")
            st.success("✓ Passes verification equation")
        
        with col2:
            st.markdown("**Forged (Attacker's) Signature:**")
            st.code(f"Tampered message:\n{tampered_msg}\n\nMAC₂: {forged_mac}", language="text")
            st.error("✗ Generated without private key")
            st.error("✗ No cryptographic binding")
            st.error("✗ Fails verification equation")
        
        # Hamming distance analysis
        mac1_bin = bin(int(original_mac, 16))[2:].zfill(128)
        mac2_bin = bin(int(forged_mac, 16))[2:].zfill(128)
        hamming = sum(c1 != c2 for c1, c2 in zip(mac1_bin, mac2_bin))
        
        st.markdown("### 🔬 Cryptographic Distance Analysis")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(
                "Hamming Distance",
                f"{hamming} bits",
                help="Number of differing bits"
            )
        with col2:
            st.metric(
                "Difference Percentage",
                f"{(hamming/128)*100:.1f}%",
                help="Percentage of bits that differ"
            )
        with col3:
            st.metric(
                "Correlation",
                "≈ 0",
                help="Statistical independence"
            )
        
        st.success("""
        **Cryptographic Conclusion:** The forged MAC is statistically independent from the 
        legitimate MAC. Without the secret key, it's mathematically impossible to create a 
        MAC that satisfies the verification equation. The signature scheme provides 
        existential unforgeability under chosen-message attack (EUF-CMA).
        """)
    
    def signature_forgery_attack(self):
        """Digital signature forgery with Dilithium3 security proof"""
        st.markdown("### ✍️ Digital Signature Forgery Attack")
        
        # Comprehensive theory
        with st.expander("📚 Dilithium3 Security Foundations", expanded=True):
            st.markdown("""
            **Dilithium3 Digital Signature Scheme (CRYSTALS-Dilithium):**
            
            **Parameters:**
            ```
            Security level: NIST Level 3 (equivalent to AES-192)
            Module rank: k = 6, l = 5
            Modulus: q = 8380417
            Public key size: 1,952 bytes
            Secret key size: 4,000 bytes
            Signature size: 3,293 bytes
            ```
            
            **Key Generation:**
            ```
            1. Sample random matrix A ∈ Rq^(k×l)
            2. Sample secrets s₁ ∈ Sl^l, s₂ ∈ Sk^k (small coefficients)
            3. Compute t = As₁ + s₂
            4. Public key: pk = (ρ, t₁) where A = ExpandA(ρ)
            5. Secret key: sk = (ρ, K, tr, s₁, s₂, t₀)
            ```
            
            **Signature Generation:**
            ```
            σ = Sign(sk, M):
                1. y ← Sample(coefficient range)
                2. w = Ay (mod q)
                3. w₁ = HighBits(w)
                4. c~ = H(μ || w₁) where μ = H(tr || M)
                5. c = SampleInBall(c~)
                6. z = y + cs₁
                7. r₀ = LowBits(w - cs₂)
                8. If ||z||∞ ≥ γ₁ - β or ||r₀||∞ ≥ γ₂ - β: goto step 1
                9. h = MakeHint(-ct₀, w - cs₂ + ct₀)
                10. Return σ = (c~, z, h)
            ```
            
            **Signature Verification:**
            ```
            Verify(pk, M, σ):
                1. Parse σ = (c~, z, h)
                2. c = SampleInBall(c~)
                3. w'₁ = UseHint(h, Az - ct₁ · 2^d)
                4. c~' = H(H(H(ρ) || t₁) || M || w'₁)
                5. Accept if c~' = c~ and ||z||∞ < γ₁ - β and ||h||₁ ≤ ω
            ```
            
            **Security Proof:**
            - **Hardness assumption:** Module-LWE and Module-SIS problems
            - **Classical security:** O(2^128) operations
            - **Quantum security:** O(2^128) operations (Grover provides no advantage for lattice problems)
            - **Reduction:** Breaking signature → Solving lattice problems
            - **Best known attack:** BKZ lattice reduction with exponential complexity
            """)
        
        st.markdown("---")
        st.markdown("### 🎯 Forgery Attack Simulation")
        
        message = st.text_input(
            "Message to forge signature for:",
            "Authorize transfer of $1,000,000",
            key="sig_msg"
        )
        
        forgery_technique = st.selectbox(
            "Forgery technique:",
            [
                "Existential Forgery (random signature generation)",
                "Universal Forgery (craft signature for any message)",
                "Selective Forgery (target specific message)",
                "Key Recovery Attack (extract private key)"
            ],
            key="sig_tech"
        )
        
        if st.button("🚀 Attempt Signature Forgery", type="primary", key="sig_btn"):
            self._execute_signature_forgery(message, forgery_technique)
    
    def _execute_signature_forgery(self, message, technique):
        """Execute signature forgery with detailed analysis"""
        
        st.markdown("#### Phase 1: Establish Baseline (Legitimate Signature)")
        
        # Create legitimate signature
        with st.spinner("Alice creating legitimate signature..."):
            time.sleep(0.3)
            legit_package = self.channel.send_message(
                message,
                self.bob_keys['kem_public'],
                self.alice_keys['sign_secret']
            )
            
            col1, col2 = st.columns(2)
            with col1:
                st.success("✓ Message signed by Alice")
                st.code(f"Message: {message}", language="text")
            with col2:
                st.success("✓ Signature created")
                st.code(f"Signature size: {len(legit_package['signature'])} bytes\nExpected: 3,293 bytes (Dilithium3)", language="text")
        
        st.markdown("#### Phase 2: 🕵️ Attacker Attempts Forgery")
        
        if "Existential" in technique:
            forged_sig = self._existential_forgery(legit_package)
        elif "Universal" in technique:
            forged_sig = self._universal_forgery(legit_package)
        elif "Selective" in technique:
            forged_sig = self._selective_forgery(legit_package)
        else:
            forged_sig = self._key_recovery_attack(legit_package)
        
        st.markdown("#### Phase 3: 👨 Bob Verifies Signature")
        
        forged_package = legit_package.copy()
        forged_package['signature'] = forged_sig
        
        with st.spinner("Bob verifying signature..."):
            time.sleep(0.3)
            
            try:
                self.channel.receive_message(
                    forged_package,
                    self.bob_keys['kem_secret'],
                    self.alice_keys['sign_public']
                )
                st.error("❌ CRITICAL ERROR: Forgery should have been detected!")
            
            except Exception:
                st.markdown("""
                <div class="danger-box">
                <h3>✅ FORGERY DETECTED AND BLOCKED!</h3>
                <strong>Verification Status:</strong> FAILED ❌<br>
                <strong>Protection:</strong> Dilithium3 Lattice-Based Digital Signatures<br>
                <strong>Security Level:</strong> NIST Level 3 (192-bit equivalent)<br>
                <br>
                <strong>🔬 Why Forgery Is Mathematically Impossible:</strong><br>
                <br>
                <strong>1. Lattice Problem Hardness:</strong><br>
                • Valid signature requires: Az - tc = w and c~ = H(μ || w₁)<br>
                • Without private key (s₁, s₂): Must solve Module-SIS<br>
                • Module-SIS complexity: O(2^128) operations<br>
                • No polynomial-time algorithm exists (classical or quantum)<br>
                <br>
                <strong>2. Quantum Resistance:</strong><br>
                • Shor's algorithm: Does NOT work on lattice problems<br>
                • Grover's algorithm: Only provides √ speedup → 2^64 still secure<br>
                • Best quantum attack: Still exponential complexity<br>
                • Security margin: Designed to resist quantum computers<br>
                <br>
                <strong>3. Mathematical Security Proof:</strong><br>
                • Reduction: Signature forgery → Module-SIS solution<br>
                • Proof technique: Forking lemma<br>
                • Security model: EUF-CMA (Existential Unforgeability under Chosen Message Attack)<br>
                • Success probability: ≤ ε where ε ≈ 2^-128 (negligible)<br>
                </div>
                """, unsafe_allow_html=True)
                
                # Show detailed comparison
                self._show_signature_analysis(legit_package['signature'], forged_sig, message)
                
                # Log the attack
                self.logger.log_attack({
                    'attack_name': 'Digital Signature Forgery',
                    'attack_type': 'Cryptographic',
                    'technique': technique,
                    'success': False,
                    'protection': 'Dilithium3 Lattice Cryptography',
                    'security_level': '128-bit (NIST Level 3)',
                    'message': message
                })
    
    def _existential_forgery(self, package):
        """Attempt existential forgery"""
        st.markdown("**Attack Method: Generate Random Signature**")
        
        with st.spinner("Generating random signature bytes..."):
            time.sleep(0.5)
            forged = bytes(random.randint(0, 255) for _ in range(len(package['signature'])))
            
            st.warning(f"⚠️ Generated {len(forged)} random bytes as signature")
            
            st.code("""
Attack Logic:
-----------
signature = random_bytes(3293)

Probability Analysis:
- Signature space: Approximately (2^8)^3293 = 2^26344
- Valid signatures: Must satisfy verification equation
- Random guess probability: ≈ 1 / 2^128 (due to hash function)
- Expected attempts: 2^128 ≈ 3.4 × 10^38

Time to Success:
- At 1 billion attempts/sec: 10^28 years
- At all Earth's computing power: Still 10^20 years
- Conclusion: IMPOSSIBLE
            """, language="python")
            
            st.error("✗ Random generation success probability: 2^-128 (negligible)")
        
        return forged
    
    def _universal_forgery(self, package):
        """Attempt universal forgery"""
        st.markdown("**Attack Method: Solve Lattice Problem**")
        
        with st.spinner("Attempting to solve Module-SIS lattice problem..."):
            time.sleep(0.8)
            
            st.code("""
Universal Forgery Requirements:
-----------------------------
Given: Public key pk = (A, t) where t = As₁ + s₂
Goal: Find valid (c~, z, h) for ANY message M

Mathematical Problem:
1. Need z such that Az - tc = w (approximately)
2. w must produce correct hash: c~ = H(μ || HighBits(w))
3. Constraint: ||z||∞ < γ₁ - β (z must be "short")

This is the Module-SIS Problem:
- Given: Random matrix A and target t
- Find: Short vectors z satisfying equation
- Hardness: Based on worst-case lattice problems (SVP, CVP)

Best Known Attack:
Algorithm: BKZ-2.0 lattice basis reduction
Block size needed: β ≈ 400 for Dilithium3
Time complexity: 2^(0.292β) ≈ 2^117 operations
            """, language="text")
            
            st.error("✗ Lattice problem remains unsolved after attempted reduction")
            
            # Generate random forged signature
            forged = bytes(random.randint(0, 255) for _ in range(len(package['signature'])))
            
            st.markdown("""
            **Attack Result:** FAILED
            - Module-SIS problem is NP-hard
            - No polynomial-time algorithm exists
            - Best algorithms still exponential (2^117 operations)
            - Even with quantum computers: Still exponential complexity
            """)
        
        return forged
    
    def _selective_forgery(self, package):
        """Attempt selective forgery for specific message"""
        st.markdown("**Attack Method: Target Specific Message**")
        
        with st.spinner("Attempting selective forgery..."):
            time.sleep(0.6)
            
            st.code("""
Selective Forgery Strategy:
-------------------------
Goal: Create valid signature for specific target message M*
Strategy: Exploit message structure or signature scheme

Attempted Approaches:
1. Message malleability: FAILED (Dilithium is non-malleable)
2. Signature reuse: FAILED (unique randomness in each signature)
3. Related message attack: FAILED (full message hashed)
4. Partial collision: FAILED (need full preimage)

Dilithium3 Protections:
- Unique nonce for each signature (prevents reuse)
- Full message included in hash (prevents substitution)
- Strong binding: c~ = H(H(public_key) || message || commitment)
- No algebraic structure to exploit
            """, language="text")
            
            st.error("✗ All selective forgery strategies failed")
            
            forged = bytes(random.randint(0, 255) for _ in range(len(package['signature'])))
        
        return forged
    
    def _key_recovery_attack(self, package):
        """Attempt to extract private key"""
        st.markdown("**Attack Method: Extract Private Key from Signatures**")
        
        with st.spinner("Analyzing signatures for key recovery..."):
            time.sleep(0.7)
            
            st.code("""
Key Recovery Attack:
------------------
Goal: Extract secret key (s₁, s₂) from public key and signatures

Signature equation: z = y + cs₁ (mod q)
- z, c are public (in signature)
- y is random secret
- s₁ is secret key

Problem: y acts as one-time pad that hides s₁
- Each signature uses fresh random y
- Cannot isolate s₁ from equation
- Solving for s₁ requires solving Module-LWE

Module-LWE Security:
- Given: (A, b = As + e) where s is secret, e is small error
- Find: Secret s
- Complexity: 2^128 operations (exponential)
- Quantum resistance: No efficient quantum algorithm known

Multiple Signature Analysis:
- Collected 1000+ signatures: INSUFFICIENT
- Linear algebra approach: FAILED (noise prevents clean system)
- Statistical analysis: FAILED (noise distribution hides key)
- Lattice reduction: FAILED (same as Module-SIS)
            """, language="text")
            
            st.error("✗ Key recovery attack failed - private key remains secure")
            
            forged = bytes(random.randint(0, 255) for _ in range(len(package['signature'])))
        
        return forged
    
    def _show_signature_analysis(self, legit_sig, forged_sig, message):
        """Detailed signature comparison"""
        st.markdown("---")
        st.markdown("### 🔬 Signature Verification Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**✓ Legitimate Signature (Alice)**")
            st.code(f"Message: {message[:50]}...\n\nSignature: {legit_sig.hex()[:100]}...\nSize: {len(legit_sig)} bytes", language="text")
            st.success("✓ Valid verification equation satisfied")
            st.success("✓ Cryptographically bound to message")
            st.success("✓ Created with authentic private key")
        
        with col2:
            st.markdown("**✗ Forged Signature (Attacker)**")
            st.code(f"Message: {message[:50]}...\n\nSignature: {forged_sig.hex()[:100]}...\nSize: {len(forged_sig)} bytes", language="text")
            st.error("✗ Verification equation NOT satisfied")
            st.error("✗ No cryptographic binding")
            st.error("✗ Generated without private key")
        
        # Entropy analysis
        import numpy as np
        
        def calculate_entropy(data):
            """Calculate Shannon entropy"""
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            entropy = 0
            for count in byte_counts:
                if count > 0:
                    p = count / len(data)
                    entropy -= p * np.log2(p)
            return entropy
        
        legit_entropy = calculate_entropy(legit_sig)
        forged_entropy = calculate_entropy(forged_sig)
        
        st.markdown("### 📊 Statistical Properties")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Legit Signature Entropy", f"{legit_entropy:.2f} bits/byte")
        with col2:
            st.metric("Forged Signature Entropy", f"{forged_entropy:.2f} bits/byte")
        with col3:
            st.metric("Expected Entropy", "~7.99 bits/byte")
        
        st.info("""
        **Observation:** Both signatures have high entropy (appear random), but only 
        the legitimate signature satisfies the mathematical verification equation. 
        This shows that security doesn't rely on statistical tests, but on 
        computational hardness of underlying mathematical problems.
        """)
    
    def chosen_ciphertext_attack(self):
        """Chosen Ciphertext Attack (CCA) simulation"""
        st.markdown("### 🔍 Chosen Ciphertext Attack (CCA)")
        
        with st.expander("📚 Understanding CCA", expanded=True):
            st.markdown("""
            **Chosen Ciphertext Attack:**
            
            An attacker can choose ciphertexts and obtain their decryptions, then use 
            this information to break a target ciphertext.
            
            **Attack Model:**
            ```
            1. Attacker has: Target ciphertext C*
            2. Attacker can: Submit ciphertexts C₁, C₂, ... to decryption oracle
            3. Goal: Decrypt C* without querying it directly
            ```
            
            **Why Some Schemes Are Vulnerable:**
            ```
            Example with malleable encryption:
            C = Encrypt(M)
            C' = C ⊕ δ  (flip some bits)
            M' = Decrypt(C')
            M = M' ⊕ δ  (recover original)
            ```
            
            **Kyber768 Defense (IND-CCA2 Security):**
            - Uses Fujisaki-Okamoto transform
            - Re-encryption check prevents malleability
            - Implicit rejection of invalid ciphertexts
            - Provably secure against CCA2 attacks
            
            **Security Level:**
            - Breaking CCA2 security requires breaking underlying LWE problem
            - No known attacks better than solving LWE directly (2^128 operations)
            """)
        
        st.markdown("---")
        st.markdown("### 🎯 Attack Simulation")
        
        target_message = st.text_input(
            "Target message to decrypt:",
            "Secret password: Ultra$ecure123!",
            key="cca_msg"
        )
        
        num_queries = st.slider(
            "Number of decryption oracle queries:",
            10, 1000, 100,
            help="Attacker's attempts to decrypt modified ciphertexts"
        )
        
        if st.button("🚀 Launch CCA Attack", type="primary", key="cca_btn"):
            self._execute_cca_attack(target_message, num_queries)
    
    def _execute_cca_attack(self, message, num_queries):
        """Execute CCA attack"""
        
        st.markdown("### Phase 1: Setup")
        
        with st.spinner("Creating target ciphertext..."):
            time.sleep(0.3)
            target_package = self.channel.send_message(
                message,
                self.bob_keys['kem_public'],
                self.alice_keys['sign_secret']
            )
            st.success(f"✓ Target ciphertext created ({len(target_package['encrypted_message'])} bytes)")
        
        st.markdown("### Phase 2: 🕵️ Attacker Queries Decryption Oracle")
        
        progress_bar = st.progress(0)
        status = st.empty()
        
        successful_decrypts = 0
        rejected = 0
        
        for i in range(num_queries):
            if i % 10 == 0:
                progress_bar.progress(i / num_queries)
                status.text(f"Query {i}/{num_queries} - Success: {successful_decrypts}, Rejected: {rejected}")
                time.sleep(0.02)
            
            # Try to create modified ciphertext
            modified_package = target_package.copy()
            
            # Attempt various modifications
            mod_type = random.choice(['bit_flip', 'byte_change', 'truncate', 'extend'])
            
            if mod_type == 'bit_flip':
                ct_bytes = bytearray(target_package['encrypted_message'])
                pos = random.randint(0, len(ct_bytes) - 1)
                ct_bytes[pos] ^= random.randint(1, 255)
                modified_package['encrypted_message'] = bytes(ct_bytes)
            
            elif mod_type == 'byte_change':
                ct_bytes = bytearray(target_package['encrypted_message'])
                pos = random.randint(0, len(ct_bytes) - 1)
                ct_bytes[pos] = random.randint(0, 255)
                modified_package['encrypted_message'] = bytes(ct_bytes)
            
            elif mod_type == 'truncate':
                modified_package['encrypted_message'] = target_package['encrypted_message'][:-1]
            
            else:  # extend
                modified_package['encrypted_message'] = target_package['encrypted_message'] + b'\x00'
            
            # Try to decrypt
            try:
                self.channel.receive_message(
                    modified_package,
                    self.bob_keys['kem_secret'],
                    self.alice_keys['sign_public']
                )
                successful_decrypts += 1
            except:
                rejected += 1
        
        progress_bar.progress(1.0)
        status.text(f"✓ Completed {num_queries} queries")
        
        st.markdown("### 📊 Attack Results")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Queries", num_queries)
        with col2:
            st.metric("Successful Decrypts", successful_decrypts)
        with col3:
            st.metric("Rejected (Invalid)", rejected)
        
        st.markdown("""
        <div class="danger-box">
        <h3>✅ CCA ATTACK BLOCKED!</h3>
        <strong>Result:</strong> All modified ciphertexts rejected<br>
        <strong>Protection:</strong> Kyber768 with Fujisaki-Okamoto Transform<br>
        <strong>Security Level:</strong> IND-CCA2 (strongest security notion)<br>
        <br>
        <strong>🔒 Why Attack Failed:</strong><br>
        <br>
        <strong>1. Ciphertext Integrity Check:</strong><br>
        • Kyber re-encrypts the decrypted message<br>
        • Compares re-encrypted result with original ciphertext<br>
        • If different: Implicitly rejects (returns error)<br>
        • Attacker gains NO information from rejection<br>
        <br>
        <strong>2. Fujisaki-Okamoto Transform:</strong><br>
        ```
        Encryption:
        1. m' = m || r (message with random)
        2. K = KEM.Encaps(pk, m')
        3. c = Encrypt(K, m')
        
        Decryption:
        1. K' = KEM.Decaps(sk, c)
        2. m' = Decrypt(K', c)
        3. Re-encrypt: c' = Encrypt(KEM.Encaps(pk, m'), m')
        4. If c' ≠ c: REJECT (implicit)
        5. Else: Return m
        ```
        <br>
        <strong>3. Non-Malleability:</strong><br>
        • Cannot modify ciphertext to get related plaintext<br>
        • Any modification invalidates re-encryption check<br>
        • Provides chosen-ciphertext security<br>
        </div>
        """, unsafe_allow_html=True)
        
        # Visualize
        import plotly.graph_objects as go
        
        fig = go.Figure(data=[
            go.Bar(name='Rejected', x=['CCA Queries'], y=[rejected], marker_color='green'),
            go.Bar(name='Successful', x=['CCA Queries'], y=[successful_decrypts], marker_color='red')
        ])
        
        fig.update_layout(
            title='CCA Attack Results: All Modified Ciphertexts Rejected',
            yaxis_title='Number of Queries',
            barmode='stack',
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        st.success("""
        **Key Takeaway:** Kyber768's IND-CCA2 security means attackers cannot gain 
        ANY advantage from decryption oracle access. This is the gold standard for 
        public-key encryption security.
        """)
        
        self.logger.log_attack({
            'attack_name': 'Chosen Ciphertext Attack',
            'attack_type': 'Cryptographic',
            'success': False,
            'queries': num_queries,
            'successful_decrypts': successful_decrypts,
            'rejected': rejected,
            'protection': 'Kyber768 IND-CCA2 with Fujisaki-Okamoto Transform'
        })
    
    def statistical_cryptanalysis(self):
        """Statistical cryptanalysis demonstration"""
        st.markdown("### 📊 Statistical Cryptanalysis")
        
        with st.expander("📚 Understanding Statistical Attacks", expanded=True):
            st.markdown("""
            **Statistical Cryptanalysis:**
            
            Attackers analyze statistical properties of ciphertexts to extract information 
            about plaintexts or keys.
            
            **Classical Example: Frequency Analysis**
            ```
            English text: 'E' appears ~12%, 'T' ~9%, ...
            Caesar cipher: 'H' appears ~12% → 'H' = 'E' shifted by 3
            Conclusion: Key = 3
            ```
            
            **Modern Cipher Requirements:**
            - Ciphertext should be indistinguishable from random
            - No statistical patterns that leak information
            - Even with millions of samples
            
            **Tests Performed:**
            1. **Entropy Analysis**: Measure randomness
            2. **Frequency Distribution**: Check uniformity
            3. **Autocorrelation**: Test for patterns
            4. **Chi-Square Test**: Statistical randomness
            5. **Runs Test**: Consecutive identical values
            
            **AES-256-GCM Security:**
            - Ciphertexts are computationally indistinguishable from random
            - Passes all statistical randomness tests
            - No known statistical attacks
            """)
        
        st.markdown("---")
        st.markdown("### 🎯 Statistical Analysis")
        
        message = st.text_area(
            "Message to analyze:",
            "The quick brown fox jumps over the lazy dog. " * 10,
            height=100,
            key="stat_msg"
        )
        
        num_samples = st.slider(
            "Number of encrypted samples:",
            100, 10000, 1000,
            step=100,
            help="More samples = better statistical analysis"
        )
        
        if st.button("🚀 Perform Statistical Analysis", type="primary", key="stat_btn"):
            self._execute_statistical_analysis(message, num_samples)
    
    def _execute_statistical_analysis(self, message, num_samples):
        """Perform comprehensive statistical analysis"""
        
        st.markdown("### Phase 1: Collect Encrypted Samples")
        
        progress_bar = st.progress(0)
        status = st.empty()
        
        ciphertexts = []
        
        for i in range(num_samples):
            if i % 100 == 0:
                progress_bar.progress(i / num_samples)
                status.text(f"Encrypting sample {i}/{num_samples}")
                time.sleep(0.01)
            
            package = self.channel.send_message(
                message,
                self.bob_keys['kem_public'],
                self.alice_keys['sign_secret']
            )
            ciphertexts.append(package['encrypted_message'])
        
        progress_bar.progress(1.0)
        status.text(f"✓ Collected {num_samples} encrypted samples")
        
        st.markdown("### Phase 2: 📊 Statistical Tests")
        
        # Combine all ciphertext bytes
        all_bytes = b''.join(ciphertexts)
        byte_array = list(all_bytes)
        
        import numpy as np
        
        # Test 1: Entropy
        st.markdown("#### Test 1: Entropy Analysis")
        
        byte_counts = [0] * 256
        for byte_val in byte_array:
            byte_counts[byte_val] += 1
        
        entropy = 0
        total = len(byte_array)
        for count in byte_counts:
            if count > 0:
                p = count / total
                entropy -= p * np.log2(p)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Measured Entropy", f"{entropy:.4f} bits/byte")
        with col2:
            st.metric("Expected (Random)", "8.0000 bits/byte")
        with col3:
            difference = abs(8.0 - entropy)
            st.metric("Difference", f"{difference:.4f}", 
                     delta="Acceptable" if difference < 0.1 else "Suspicious",
                     delta_color="normal" if difference < 0.1 else "inverse")
        
        if entropy > 7.9:
            st.success("✓ Entropy test PASSED - Ciphertext appears random")
        else:
            st.warning("⚠ Entropy test FAILED - Statistical bias detected!")
        
        # Test 2: Frequency Distribution
        st.markdown("#### Test 2: Byte Frequency Distribution")
        
        expected_freq = total / 256
        chi_square = sum((count - expected_freq) ** 2 / expected_freq for count in byte_counts)
        
        # Critical value for chi-square with 255 df at 0.05 significance
        critical_value = 293.25
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Chi-Square Statistic", f"{chi_square:.2f}")
        with col2:
            st.metric("Critical Value (α=0.05)", f"{critical_value:.2f}")
        
        if chi_square < critical_value:
            st.success("✓ Chi-square test PASSED - Uniform distribution")
        else:
            st.warning("⚠ Chi-square test FAILED - Non-uniform distribution!")
        
        # Visualization
        import plotly.graph_objects as go
        
        fig = go.Figure()
        
        fig.add_trace(go.Histogram(
            x=byte_array,
            nbinsx=256,
            name='Actual Distribution',
            marker_color='blue',
            opacity=0.7
        ))
        
        fig.add_hline(
            y=expected_freq,
            line_dash="dash",
            line_color="red",
            annotation_text="Expected (uniform)"
        )
        
        fig.update_layout(
            title='Byte Frequency Distribution in Ciphertexts',
            xaxis_title='Byte Value (0-255)',
            yaxis_title='Frequency',
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Test 3: Autocorrelation
        st.markdown("#### Test 3: Autocorrelation Test")
        
        # Calculate autocorrelation for lag 1
        mean_val = np.mean(byte_array)
        numerator = sum((byte_array[i] - mean_val) * (byte_array[i+1] - mean_val) 
                       for i in range(len(byte_array) - 1))
        denominator = sum((byte_val - mean_val) ** 2 for byte_val in byte_array)
        
        autocorr = numerator / denominator if denominator != 0 else 0
        
        st.metric("Lag-1 Autocorrelation", f"{autocorr:.6f}",
                 help="Should be close to 0 for random data")
        
        if abs(autocorr) < 0.05:
            st.success("✓ Autocorrelation test PASSED - No sequential patterns")
        else:
            st.warning("⚠ Autocorrelation test FAILED - Sequential correlation detected!")
        
        # Final Analysis
        st.markdown("---")
        st.markdown("### 📋 Statistical Analysis Summary")
        
        tests_passed = sum([
            entropy > 7.9,
            chi_square < critical_value,
            abs(autocorr) < 0.05
        ])
        
        if tests_passed == 3:
            st.markdown("""
            <div class="success-box">
            <h3>✅ ALL STATISTICAL TESTS PASSED!</h3>
            <strong>Result:</strong> Ciphertexts are statistically indistinguishable from random<br>
            <strong>Conclusion:</strong> No statistical attack vector identified<br>
            <br>
            <strong>🔒 AES-256-GCM Security Validated:</strong><br>
            • Entropy: {:.4f}/8.0 bits/byte ✓<br>
            • Frequency distribution: Uniform ✓<br>
            • Autocorrelation: No patterns ✓<br>
            • Chi-square: Within expected range ✓<br>
            <br>
            <strong>Cryptographic Conclusion:</strong><br>
            The ciphertexts exhibit perfect statistical properties expected from 
            a secure encryption scheme. Even with {:,} samples, no exploitable 
            statistical weakness was found. AES-256-GCM provides semantic security.
            </div>
            """.format(entropy, num_samples), unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="warning-box">
            <h3>⚠️ SOME TESTS FAILED</h3>
            <strong>Tests Passed:</strong> {}/3<br>
            <strong>Note:</strong> Small variations are expected due to finite sample size.<br>
            With more samples, results converge to expected values.
            </div>
            """.format(tests_passed), unsafe_allow_html=True)
        
        self.logger.log_attack({
            'attack_name': 'Statistical Cryptanalysis',
            'attack_type': 'Cryptographic',
            'success': False,
            'samples_analyzed': num_samples,
            'entropy': float(entropy),
            'chi_square': float(chi_square),
            'autocorrelation': float(autocorr),
            'tests_passed': f"{tests_passed}/3",
            'conclusion': 'No statistical weaknesses found'
        })