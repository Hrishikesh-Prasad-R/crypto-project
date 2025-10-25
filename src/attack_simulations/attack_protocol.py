"""
Protocol-Level Attack Implementations - Complete
Attacks that succeed due to protocol weaknesses, not cryptographic failures

FILE: attack_protocol.py
"""

import streamlit as st
import time
import random
import plotly.graph_objects as go
from .attack_visualizer import AttackVisualizer


class ProtocolAttacks:
    """Protocol-level attacks that bypass cryptography"""
    
    def __init__(self, channel, alice_keys, bob_keys, logger):
        self.channel = channel
        self.alice_keys = alice_keys
        self.bob_keys = bob_keys
        self.logger = logger
        self.visualizer = AttackVisualizer()
    
    def render(self):
        """Main render method"""
        st.subheader("⚠️ Protocol-Level Attack Simulations")
        
        st.markdown("""
        <div class="warning-box">
        <strong>⚠️ Important Educational Point</strong><br>
        These attacks SUCCEED even with perfect post-quantum cryptography! 
        This demonstrates why secure systems need multiple layers of defense:
        cryptographic algorithms, secure protocols, proper implementation, and operational security.
        </div>
        """, unsafe_allow_html=True)
        
        attack_type = st.selectbox(
            "**Select Protocol Attack:**",
            [
                "🔄 Replay Attack (Transaction Duplication)",
                "🕵️ Man-in-the-Middle Attack (Without PKI)",
                "📉 Downgrade Attack (Force Weak Crypto)",
                "⏱️ Timing Side-Channel Attack"
            ]
        )
        
        st.markdown("---")
        
        if "Replay" in attack_type:
            self.replay_attack()
        elif "Man-in-the-Middle" in attack_type:
            self.mitm_attack()
        elif "Downgrade" in attack_type:
            self.downgrade_attack()
        elif "Timing" in attack_type:
            self.timing_attack()
    
    def replay_attack(self):
        """Replay attack demonstration"""
        st.markdown("### 🔄 Replay Attack")
        
        with st.expander("📚 Understanding Replay Attacks", expanded=True):
            st.markdown("""
            **What is a Replay Attack?**
            
            A replay attack occurs when an attacker intercepts a valid message and 
            retransmits it at a later time to duplicate an action.
            
            **Why Cryptography Alone Cannot Prevent It:**
            ```
            1. Alice sends: Encrypt("Transfer $500", Key) + Sign(message)
            2. Attacker intercepts: Saves encrypted message
            3. Attacker replays: Sends same encrypted message again
            4. Cryptography checks:
               - Encryption: ✓ Valid (correct key)
               - Signature: ✓ Valid (authentic signature)
               - Authentication: ✓ Valid (from Alice)
            5. Result: Transaction executed TWICE!
            ```
            
            **The Problem:**
            - The cryptographic message is VALID
            - Signature proves it came from Alice
            - Encryption proves confidentiality
            - But nothing prevents reuse!
            
            **Required Defenses (Protocol Level):**
            1. **Timestamps**: Reject messages older than threshold
            2. **Nonces**: One-time numbers that cannot be reused
            3. **Sequence numbers**: Ordered message tracking
            4. **Session tokens**: Expire after use
            """)
        
        st.markdown("---")
        st.markdown("### 🎯 Attack Simulation")
        
        # Initialize replay storage
        if 'replay_messages' not in st.session_state:
            st.session_state.replay_messages = []
        
        message = st.text_input(
            "Transaction message:",
            "Transfer $500 to Alice's account",
            key="replay_msg"
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📤 Send Legitimate Transaction", key="replay_send", type="primary"):
                self._send_transaction(message)
        
        with col2:
            if st.button("🔄 Launch Replay Attack", key="replay_attack", 
                        disabled=len(st.session_state.replay_messages) == 0):
                if st.session_state.replay_messages:
                    self._execute_replay_attack()
        
        # Show captured messages
        if st.session_state.replay_messages:
            st.markdown("---")
            st.markdown("### 📋 Intercepted Messages (Attacker's Storage)")
            
            for i, msg_data in enumerate(st.session_state.replay_messages[-5:], 1):
                age = time.time() - msg_data['timestamp']
                with st.expander(f"Message {i}: '{msg_data['message']}' ({age:.1f}s ago)"):
                    st.code(f"""
Timestamp: {time.strftime('%H:%M:%S', time.localtime(msg_data['timestamp']))}
Message: {msg_data['message']}
Encrypted size: {len(msg_data['package']['encrypted_message'])} bytes
Signature size: {len(msg_data['package']['signature'])} bytes
Cryptographic validity: ✓ VALID
Age: {age:.1f} seconds
                    """, language="text")
    
    def _send_transaction(self, message):
        """Send a legitimate transaction"""
        with st.spinner("Sending transaction..."):
            time.sleep(0.3)
            
            # Create cryptographically valid message
            package = self.channel.send_message(
                message,
                self.bob_keys['kem_public'],
                self.alice_keys['sign_secret']
            )
            
            # Store for potential replay
            st.session_state.replay_messages.append({
                'package': package,
                'message': message,
                'timestamp': time.time()
            })
            
            st.success(f"✓ Transaction sent at {time.strftime('%H:%M:%S')}")
            st.info("🕵️ **Attacker intercepted and stored the encrypted message!**")
            
            # Show what attacker sees
            st.markdown("**What the attacker captured:**")
            col1, col2 = st.columns(2)
            with col1:
                st.code(f"Ciphertext:\n{package['encrypted_message'].hex()[:100]}...", language="text")
            with col2:
                st.code(f"Signature:\n{package['signature'].hex()[:100]}...", language="text")
    
    def _execute_replay_attack(self):
        """Execute replay attack"""
        old_msg = st.session_state.replay_messages[-1]
        age = time.time() - old_msg['timestamp']
        
        st.markdown("### 🚨 Replay Attack in Progress")
        
        with st.spinner("Replaying captured message..."):
            time.sleep(0.5)
            
            st.warning(f"⚠️ Replaying message from {age:.1f} seconds ago...")
            st.code(f"Original: '{old_msg['message']}'", language="text")
        
        # Attempt to "receive" the replayed message
        try:
            decrypted = self.channel.receive_message(
                old_msg['package'],
                self.bob_keys['kem_secret'],
                self.alice_keys['sign_public']
            )
            
            # Success - attack worked!
            # Extract amount if present
            amount = "unknown"
            if '$' in old_msg['message']:
                try:
                    amount = old_msg['message'].split('$')[1].split()[0]
                except:
                    amount = "500"
            
            st.markdown(f"""
            <div class="danger-box">
            <h3>✓ REPLAY ATTACK SUCCESSFUL!</h3>
            <strong>Replayed Message:</strong> "{decrypted}"<br>
            <strong>Cryptographic Checks:</strong><br>
            • Encryption: ✓ Valid<br>
            • Signature: ✓ Valid (authentic from Alice)<br>
            • Authentication: ✓ Passed<br>
            <br>
            <strong>⚠️ IMPACT:</strong><br>
            • Transaction executed TWICE!<br>
            • Alice charged ${amount} again!<br>
            • No cryptographic defense prevented this!<br>
            <br>
            <strong>🔍 Why Cryptography Didn't Help:</strong><br>
            The replayed message IS cryptographically valid. It has:
            <ul>
            <li>Valid encryption (correct decryption)</li>
            <li>Valid signature (proves Alice sent it)</li>
            <li>Proper authentication</li>
            </ul>
            <br>
            <strong>The problem:</strong> Nothing prevents message reuse!
            </div>
            """, unsafe_allow_html=True)
            
            # Show defense mechanisms
            st.markdown("---")
            st.markdown("### 🛡️ Required Protocol-Level Defenses")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("""
                **Defense Mechanisms:**
                
                **1. Timestamps:**
                ```python
                def verify(message, signature, timestamp):
                    current_time = time.now()
                    if current_time - timestamp > 60:  # 1 minute window
                        reject("Message too old")
                    # ... rest of verification
                ```
                
                **2. Nonces (Number Used Once):**
                ```python
                used_nonces = set()
                
                def verify(message, signature, nonce):
                    if nonce in used_nonces:
                        reject("Nonce already used!")
                    used_nonces.add(nonce)
                    # ... rest of verification
                ```
                """)
            
            with col2:
                st.markdown("""
                **Implementation Example:**
                
                **3. Sequence Numbers:**
                ```python
                expected_seq = 1
                
                def verify(message, signature, seq_num):
                    if seq_num != expected_seq:
                        reject("Out of order")
                    expected_seq += 1
                    # ... rest of verification
                ```
                
                **4. Session Tokens:**
                ```python
                def verify(message, signature, session_token):
                    if not session_valid(session_token):
                        reject("Invalid/expired session")
                    expire_token(session_token)  # One-time use
                    # ... rest of verification
                ```
                """)
            
            st.success("""
            **Key Lesson:** Strong cryptography ensures confidentiality, integrity, and 
            authenticity, but **protocol-level mechanisms** are needed to prevent replay attacks. 
            Real-world systems like TLS use sequence numbers and nonces to defend against this.
            """)
            
            # Log attack
            self.logger.log_attack({
                'attack_name': 'Replay Attack',
                'attack_type': 'Protocol',
                'success': True,
                'message': old_msg['message'],
                'age_seconds': age,
                'lesson': 'Protocol-level nonce/timestamp tracking required'
            })
            
        except Exception as e:
            st.error(f"Unexpected error: {e}")
    
    def mitm_attack(self):
        """Man-in-the-middle attack without PKI"""
        st.markdown("### 🕵️ Man-in-the-Middle Attack (No PKI)")
        
        with st.expander("📚 Understanding MITM Attacks", expanded=True):
            st.markdown("""
            **Man-in-the-Middle (MITM) Attack:**
            
            An attacker intercepts communications and poses as each party to the other.
            
            **The Scenario:**
            ```
            Alice wants to send encrypted message to Bob
            
            Normal:
            Alice --[using Bob's public key]--> Bob
            
            With MITM:
            Alice --[using Eve's public key]--> Eve --[using Bob's public key]--> Bob
                    (thinks it's Bob's key)         (Eve reads everything!)
            ```
            
            **Why It Works:**
            - Alice encrypts with what she THINKS is Bob's public key
            - But it's actually Eve's public key (Eve substituted it)
            - Eve can decrypt, read, and re-encrypt for Bob
            - Cryptography works perfectly... for the wrong key!
            
            **The Missing Piece: PKI (Public Key Infrastructure)**
            ```
            Without PKI:
            - Alice receives key claiming to be "Bob's key"
            - No way to verify it actually belongs to Bob
            - Eve can substitute her own key
            
            With PKI (Certificates):
            - Bob's key comes with certificate from trusted CA
            - Certificate cryptographically binds key to Bob's identity
            - Eve cannot forge certificate without CA's private key
            - Alice can verify Bob's identity
            ```
            
            **Defense: Certificate Authorities (like HTTPS)**
            - Trusted third party (CA) signs public keys
            - Browser/client verifies certificate chain
            - Prevents key substitution
            """)
        
        st.markdown("---")
        st.markdown("### 🎯 Attack Simulation")
        
        message = st.text_input(
            "Alice's confidential message:",
            "Meet at the secret location at midnight",
            key="mitm_msg"
        )
        
        if st.button("🚀 Simulate MITM Attack", type="primary", key="mitm_btn"):
            self._execute_mitm_attack(message)
    
    def _execute_mitm_attack(self, message):
        """Execute MITM attack demonstration"""
        
        st.markdown("### 📡 Attack Execution")
        
        # Phase 1: Eve generates malicious keys
        st.markdown("#### Phase 1: 🕵️ Eve Prepares Attack")
        with st.spinner("Eve generating her own key pair..."):
            time.sleep(0.4)
            eve_keys = self.channel.generate_keys()
            st.success("✓ Eve has generated her own Kyber768 + Dilithium3 keys")
            st.code(f"Eve's public key size: {len(eve_keys['kem_public'])} bytes", language="text")
        
        # Phase 2: Alice sends (to wrong key)
        st.markdown("#### Phase 2: 👩 Alice Encrypts Message")
        st.warning("⚠️ Alice thinks she's using Bob's key, but Eve substituted hers!")
        
        with st.spinner("Alice encrypting..."):
            time.sleep(0.4)
            
            # Alice encrypts with Eve's key (thinking it's Bob's)
            package_to_eve = self.channel.send_message(
                message,
                eve_keys['kem_public'],  # Wrong key!
                self.alice_keys['sign_secret']
            )
            
            st.info("✓ Message encrypted with Eve's public key (Alice doesn't know!)")
        
        # Phase 3: Eve intercepts and decrypts
        st.markdown("#### Phase 3: 🕵️ Eve Intercepts and Decrypts")
        with st.spinner("Eve decrypting message..."):
            time.sleep(0.4)
            
            try:
                # Eve can decrypt because it was encrypted with HER public key
                decrypted_by_eve = self.channel.receive_message(
                    package_to_eve,
                    eve_keys['kem_secret'],  # Eve's private key
                    self.alice_keys['sign_public']
                )
                
                st.markdown(f"""
                <div class="danger-box">
                <h3>🚨 EVE SUCCESSFULLY READ THE MESSAGE!</h3>
                <strong>Decrypted Message:</strong> "{decrypted_by_eve}"<br>
                <strong>Signature Verification:</strong> ✓ Valid (authentically from Alice)<br>
                <strong>Encryption:</strong> ✓ Valid (Eve had the right key)<br>
                <br>
                <strong>🕵️ Eve now knows Alice's secret!</strong>
                </div>
                """, unsafe_allow_html=True)
                
                # Phase 4: Eve tries to forward to Bob
                st.markdown("#### Phase 4: 🕵️ Eve Attempts to Forward to Bob")
                st.info("Eve wants to forward the message to Bob so he doesn't suspect anything...")
                
                with st.spinner("Eve re-encrypting for Bob..."):
                    time.sleep(0.3)
                    
                    # Eve creates new package for Bob
                    package_to_bob = self.channel.send_message(
                        decrypted_by_eve,
                        self.bob_keys['kem_public'],
                        eve_keys['sign_secret']  # Eve signs with HER key!
                    )
                    
                    st.warning("⚠️ Eve re-encrypted the message, but signed with HER private key")
                
                # Phase 5: Bob verifies
                st.markdown("#### Phase 5: 👨 Bob Attempts to Verify")
                with st.spinner("Bob verifying signature..."):
                    time.sleep(0.3)
                    
                    try:
                        # Bob expects Alice's signature
                        self.channel.receive_message(
                            package_to_bob,
                            self.bob_keys['kem_secret'],
                            self.alice_keys['sign_public']  # Expecting Alice's key!
                        )
                        st.error("This shouldn't happen - signature should fail!")
                    except:
                        st.success("✓ Bob detected the forged signature!")
                        st.info("The signature doesn't match Alice's public key")
                
                # Analysis
                st.markdown("---")
                st.markdown("### 📊 Attack Analysis")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("""
                    **✓ What Worked (Attacker's Success):**
                    - Eve intercepted the communication
                    - Eve read Alice's confidential message
                    - Key substitution succeeded
                    - Alice had no way to verify key ownership
                    - Cryptography worked perfectly (for wrong key!)
                    """)
                
                with col2:
                    st.markdown("""
                    **✗ What Failed (Attacker's Limitation):**
                    - Eve cannot forge Alice's signature
                    - Bob detected signature mismatch
                    - Attack was ultimately detected
                    - Eve cannot impersonate Alice to Bob
                    """)
                
                st.markdown("---")
                st.markdown("### 🛡️ Complete Defense Strategy")
                
                st.success("""
                **Multi-Layer Defense Required:**
                
                **Layer 1: Encryption (✓ Already Have)**
                - Prevents passive eavesdropping
                - Kyber768 provides quantum-resistant encryption
                
                **Layer 2: Digital Signatures (✓ Already Have)**
                - Prevents forgery and impersonation
                - Dilithium3 provides quantum-resistant signatures
                - Detected Eve's forwarding attempt
                
                **Layer 3: Public Key Infrastructure - PKI (✗ MISSING)**
                - Certificates bind public keys to identities
                - Certificate Authority (CA) signs certificates
                - Clients verify certificate chains
                - Prevents key substitution attacks
                - **This is what HTTPS/TLS provides!**
                
                **Example: TLS Certificate Chain**
                ```
                Root CA
                  └─> Intermediate CA
                        └─> Bob's Certificate
                              • Public key: [Bob's key]
                              • Owner: Bob
                              • Signed by: Intermediate CA
                
                Alice verifies:
                1. Bob's cert signed by Intermediate CA ✓
                2. Intermediate cert signed by Root CA ✓
                3. Root CA in trusted store ✓
                4. Certificate not expired ✓
                5. Certificate not revoked ✓
                → Now Alice knows the key truly belongs to Bob!
                ```
                
                **Layer 4: Certificate Transparency**
                - Public logs of all certificates
                - Detects mis-issued certificates
                - Additional protection against CA compromise
                """)
                
                # Visualization
                st.markdown("### 📈 Defense Layer Effectiveness")
                
                categories = ['Eavesdropping', 'Tampering', 'Forgery', 'MITM']
                pqc_only = [100, 100, 100, 30]  # MITM partially successful
                pqc_plus_pki = [100, 100, 100, 100]  # All blocked
                
                fig = self.visualizer.create_radar_chart(
                    categories, pqc_plus_pki, pqc_only
                )
                
                # Update trace names
                fig.data[0].name = 'PQC + PKI (Complete)'
                fig.data[1].name = 'PQC Only (Incomplete)'
                
                st.plotly_chart(fig, use_container_width=True)
                
                st.warning("""
                **Critical Lesson:** Strong cryptography (PQC) is essential but not sufficient. 
                Real-world security requires:
                1. Strong encryption algorithms (Kyber768) ✓
                2. Strong signature algorithms (Dilithium3) ✓
                3. Public Key Infrastructure (certificates) ← ESSENTIAL!
                4. Secure key exchange protocols (TLS 1.3 + PQC)
                5. Proper implementation and validation
                """)
                
                # Log attack
                self.logger.log_attack({
                    'attack_name': 'Man-in-the-Middle Attack',
                    'attack_type': 'Protocol',
                    'success': True,  # Partially successful
                    'message': message,
                    'lesson': 'PKI/Certificates required for key authentication',
                    'what_worked': 'Key substitution, message interception',
                    'what_failed': 'Signature forgery detected'
                })
                
            except Exception as e:
                st.error(f"Error during attack simulation: {e}")
    
    def downgrade_attack(self):
        """Downgrade attack simulation"""
        st.markdown("### 📉 Downgrade Attack")
        
        with st.expander("📚 Understanding Downgrade Attacks", expanded=True):
            st.markdown("""
            **What is a Downgrade Attack?**
            
            An attacker forces the use of weaker/older cryptographic algorithms by 
            manipulating protocol negotiation.
            
            **The Threat: "Harvest Now, Decrypt Later"**
            ```
            2024: Attacker intercepts RSA-2048 encrypted traffic
                  → Cannot decrypt now (classical computers insufficient)
            
            2030: Quantum computers become available
                  → Shor's algorithm breaks RSA in minutes
                  → Decrypt all stored traffic from 2024!
            ```
            
            **Attack Mechanism:**
            ```
            Normal Negotiation:
            Client: I support [Kyber768, Dilithium3, RSA-4096, AES-256]
            Server: Let's use Kyber768 (strongest available)
            Result: ✓ Quantum-resistant communication
            
            With Downgrade Attack:
            Client: I support [Kyber768, Dilithium3, RSA-4096, AES-256]
            ↓ [Attacker modifies]
            Server receives: I support [RSA-2048, AES-128]
            Server: Let's use RSA-2048 (only option available)
            Result: ✗ Vulnerable to future quantum attacks!
            ```
            
            **Real-World Examples:**
            - **FREAK attack (2015)**: Forced export-grade 512-bit RSA
            - **POODLE attack (2014)**: Downgraded TLS to SSL 3.0
            - **DROWN attack (2016)**: Exploited SSLv2 support
            
            **Defense Mechanisms:**
            1. **Strict TLS Policy**: Minimum version enforcement
            2. **Signed Negotiation**: Cryptographically sign algorithm list
            3. **HSTS-like for PQC**: Force PQC when available
            4. **Fail-Closed**: Reject connection if PQC not available
            """)
        
        st.markdown("---")
        st.markdown("### 🎯 Attack Simulation")
        
        message = st.text_input(
            "Confidential message:",
            "Product launch date: March 15, 2026 - Project Quantum",
            key="down_msg"
        )
        
        if st.button("🚀 Simulate Downgrade Attack", type="primary", key="down_btn"):
            self._execute_downgrade_attack(message)
    
    def _execute_downgrade_attack(self, message):
        """Execute downgrade attack"""
        
        st.markdown("### 📡 Protocol Negotiation Attack")
        
        # Step 1: Normal negotiation
        st.markdown("#### Step 1: Normal Protocol Negotiation")
        with st.spinner("Client and server negotiating..."):
            time.sleep(0.5)
            
            st.code("""
Client (Alice) proposes:
- Kyber768 (PQC KEM) - NIST Level 3
- Dilithium3 (PQC Signature) - NIST Level 3  
- RSA-4096 (Classical, legacy support)
- RSA-2048 (Classical, legacy support)

Server (Bob) supports:
- Kyber768 (PQC KEM)
- Dilithium3 (PQC Signature)
- RSA-4096 (Classical)
- RSA-2048 (Classical)

Expected Result: Use Kyber768 + Dilithium3 (strongest available)
            """, language="text")
            
            st.success("✓ Normal negotiation would select: **Kyber768 + Dilithium3** (Quantum-resistant)")
        
        # Step 2: Attacker interference
        st.markdown("#### Step 2: 🕵️ Attacker Intercepts and Modifies")
        with st.spinner("Eve modifying negotiation message..."):
            time.sleep(0.5)
            
            st.warning("⚠️ Eve intercepts the negotiation and removes PQC options!")
            
            st.code("""
Original message from Alice:
Supported: [Kyber768, Dilithium3, RSA-4096, RSA-2048]

↓ [Eve modifies the list]

Modified message (what Bob receives):
Supported: [RSA-2048 only]

Bob's response:
"OK, let's use RSA-2048" (only option available)
            """, language="text")
        
        # Step 3: Result
        st.markdown("#### Step 3: ✓ Downgrade Successful")
        
        st.markdown(f"""
        <div class="danger-box">
        <h3>⚠️ DOWNGRADE ATTACK SUCCEEDED!</h3>
        <strong>Selected Protocol:</strong> RSA-2048 + SHA-256<br>
        <strong>Security Level:</strong> 112-bit classical, 0-bit quantum<br>
        <strong>Quantum Vulnerable:</strong> ✗ YES<br>
        <br>
        <strong>🕵️ Attacker's Strategy: "Harvest Now, Decrypt Later"</strong><br>
        <br>
        <strong>Phase 1 (Today - 2024):</strong><br>
        • Record all RSA-2048 encrypted traffic<br>
        • Store encrypted messages (cannot decrypt yet)<br>
        • Wait for quantum computers to become available<br>
        <br>
        <strong>Phase 2 (Future - ~2030):</strong><br>
        • Quantum computers available<br>
        • Use Shor's algorithm to factor RSA-2048<br>
        • Decrypt all stored traffic retroactively<br>
        • Alice's 2026 product launch exposed in 2031!<br>
        <br>
        <strong>⚠️ Impact:</strong><br>
        • Confidential data: {message}<br>
        • Protected today: ✓ (classical computers can't break RSA-2048)<br>
        • Protected in 2030: ✗ (quantum computers will break it)<br>
        • Shelf life: Only 6 years instead of 50+ years
        </div>
        """, unsafe_allow_html=True)
        
        # Comparison
        st.markdown("---")
        st.markdown("### 📊 Security Comparison")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            **❌ Downgraded Protocol (RSA-2048)**
            
            **Current Security:**
            - Classical computers: ✓ Secure (~112 bits)
            - Requires ~2^112 operations to break
            - Safe from classical attacks
            
            **Future Security (with quantum):**
            - Quantum computers: ✗ BROKEN
            - Shor's algorithm: Factors in polynomial time
            - Break time: Minutes to hours
            - All past data exposed
            
            **Timeline:**
            - Safe until: ~2030
            - Vulnerability: Known and inevitable
            - Risk: HIGH (future data breach)
            """)
        
        with col2:
            st.markdown("""
            **✅ Proper Protocol (Kyber768)**
            
            **Current Security:**
            - Classical computers: ✓ Secure (~184 bits)
            - Requires ~2^184 operations
            - Impossible with current technology
            
            **Future Security (with quantum):**
            - Quantum computers: ✓ Secure (~92 bits)
            - No efficient quantum algorithm exists
            - Break time: Still impossible
            - Data remains secure
            
            **Timeline:**
            - Safe until: 2070+ (50+ years)
            - Vulnerability: None known
            - Risk: LOW (future-proof)
            """)
        
        # Visualization
        st.markdown("### 📈 Security Timeline")
        
        years = list(range(2024, 2051))
        rsa_security = [100 if y < 2030 else 0 for y in years]
        pqc_security = [100] * len(years)
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=years, y=rsa_security,
            fill='tozeroy',
            name='RSA-2048 (Downgraded)',
            line=dict(color='red', width=2)
        ))
        
        fig.add_trace(go.Scatter(
            x=years, y=pqc_security,
            fill='tozeroy',
            name='Kyber768 (PQC)',
            line=dict(color='green', width=2)
        ))
        
        fig.add_vline(x=2030, line_dash="dash",
                      annotation_text="Quantum Threat (2030)",
                      line_color="red")
        
        fig.update_layout(
            title='Security Over Time: RSA-2048 vs Kyber768',
            xaxis_title='Year',
            yaxis_title='Security Level (%)',
            yaxis_range=[0, 110],
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Defense mechanisms
        st.markdown("---")
        st.markdown("### 🛡️ Defense Against Downgrade Attacks")
        
        st.success("""
        **Required Protocol-Level Protections:**
        
        **1. Signed Negotiation:**
        ```python
        # Both client and server sign the negotiation
        negotiation = {
            'algorithms': ['Kyber768', 'Dilithium3', ...],
            'timestamp': current_time()
        }
        signature = sign(negotiation, private_key)
        
        # Attacker cannot modify without invalidating signature
        ```
        
        **2. Strict Minimum Version Policy:**
        ```python
        MIN_SECURITY_LEVEL = "NIST_LEVEL_3_PQC"
        
        if negotiated_algorithm < MIN_SECURITY_LEVEL:
            reject_connection()
            log_downgrade_attempt()
        ```
        
        **3. HSTS-like Enforcement:**
        ```python
        # Like HTTP Strict Transport Security
        if previously_used_pqc(server):
            require_pqc()  # Must use PQC if previously supported
        ```
        
        **4. Certificate Transparency:**
        ```python
        # Log all negotiations publicly
        public_log.append({
            'client': alice,
            'server': bob,
            'negotiated': selected_algorithm,
            'timestamp': now()
        })
        # Makes downgrade attacks detectable
        ```
        
        **Best Practice:**
        Configure servers to **reject connections without post-quantum support** if the 
        client has PQC capability. Better to fail-closed than accept vulnerable connection.
        """)
        
        # Log attack
        self.logger.log_attack({
            'attack_name': 'Downgrade Attack',
            'attack_type': 'Protocol',
            'success': True,
            'message': message,
            'downgraded_to': 'RSA-2048',
            'lesson': 'Signed negotiation and strict protocol enforcement required'
        })
    
    def timing_attack(self):
        """Timing side-channel attack"""
        st.markdown("### ⏱️ Timing Side-Channel Attack")
        
        with st.expander("📚 Understanding Timing Attacks", expanded=True):
            st.markdown("""
            **What is a Timing Side-Channel Attack?**
            
            Attackers measure the time taken by cryptographic operations to extract 
            secret information. The timing differences leak information about secret keys.
            
            **Simple Example:**
            ```python
            def verify_password(input_password, correct_password):
                for i in range(len(input_password)):
                    if input_password[i] != correct_password[i]:
                        return False  # ← Early exit leaks information!
                return True
            
            Attack:
            - Try "a": Returns in 1µs → First character wrong
            - Try "p": Returns in 2µs → First character correct, second wrong
            - Try "pa": Returns in 3µs → First two correct
            - Continue until full password recovered!
            ```
            
            **Cryptographic Timing Attack:**
            ```
            Vulnerable code:
            if signature[0] != expected[0]:
                return False  # Different timing based on where mismatch occurs!
            
            Attacker measures:
            - Signature with wrong byte 0: 1µs
            - Signature with correct byte 0: 2µs
            → Attacker learns byte 0 is correct!
            ```
            
            **Why This Is Dangerous:**
            - Works remotely over network
            - Requires statistical analysis of many measurements
            - Can extract full cryptographic keys
            - Bypasses mathematical security
            
            **Defense: Constant-Time Implementation:**
            ```python
            def constant_time_compare(a, b):
                diff = 0
                for i in range(len(a)):
                    diff |= a[i] ^ b[i]  # Always execute all iterations
                return diff == 0  # No early exit
            ```
            
            **Additional Defenses:**
            - Constant-time algorithms (no data-dependent branches)
            - Blinding techniques
            - Random delays
            - Hardware countermeasures
            """)
        
        st.markdown("---")
        st.markdown("### 🎯 Attack Simulation")
        
        num_measurements = st.slider(
            "Number of timing measurements:",
            min_value=100,
            max_value=10000,
            value=1000,
            step=100,
            help="More measurements = more information extracted"
        )
        
        if st.button("🚀 Launch Timing Attack", type="primary", key="timing_btn"):
            self._execute_timing_attack(num_measurements)
    
    def _execute_timing_attack(self, num_measurements):
        """Execute timing side-channel attack"""
        
        st.markdown("### 📊 Collecting Timing Data")
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Simulate timing measurements
        timing_data = []
        
        for i in range(num_measurements):
            if i % 100 == 0:
                status_text.text(f"Collecting measurements: {i}/{num_measurements}")
                progress_bar.progress(i / num_measurements)
                time.sleep(0.01)
            
            # Simulate timing with secret-dependent variation
            base_time = 0.5  # Base execution time
            noise = random.gauss(0, 0.05)  # Random noise
            secret_leak = random.choice([-0.02, 0.02])  # Secret-dependent timing
            
            timing = base_time + noise + secret_leak
            timing_data.append(timing)
        
        progress_bar.progress(1.0)
        status_text.text(f"✓ Collected {num_measurements} timing measurements")
        
        # Statistical analysis
        st.markdown("---")
        st.markdown("### 📈 Statistical Analysis")
        
        import numpy as np
        timings = np.array(timing_data)
        mean_time = np.mean(timings)
        std_time = np.std(timings)
        min_time = np.min(timings)
        max_time = np.max(timings)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Mean Time", f"{mean_time:.4f} ms")
        with col2:
            st.metric("Std Deviation", f"{std_time:.4f} ms")
        with col3:
            st.metric("Min Time", f"{min_time:.4f} ms")
        with col4:
            st.metric("Max Time", f"{max_time:.4f} ms")
        
        # Visualization
        fig = go.Figure()
        
        fig.add_trace(go.Histogram(
            x=timing_data,
            nbinsx=50,
            name='Timing Distribution',
            marker_color='red'
        ))
        
        fig.update_layout(
            title='Timing Measurement Distribution',
            xaxis_title='Execution Time (ms)',
            yaxis_title='Frequency',
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Key extraction
        st.markdown("---")
        st.markdown("### 🔓 Key Bit Extraction")
        
        with st.spinner("Applying statistical correlation analysis..."):
            time.sleep(1.0)
            
            # Simulate key extraction (more samples = more bits)
            bits_per_100_samples = 0.5
            extracted_bits = int(num_measurements * bits_per_100_samples / 100)
            extracted_bits = min(extracted_bits, 256)  # Cap at reasonable amount
            
            key_size_bits = 2400 * 8  # Kyber768 secret key
            progress_pct = (extracted_bits / key_size_bits) * 100
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric(
                    "Bits Extracted",
                    f"{extracted_bits}",
                    help="Key bits recovered from timing"
                )
            
            with col2:
                st.metric(
                    "Total Key Size",
                    f"{key_size_bits} bits",
                    help="Full secret key size"
                )
            
            with col3:
                st.metric(
                    "Progress",
                    f"{progress_pct:.3f}%",
                    help="Percentage of key recovered"
                )
            
            st.markdown(f"""
            <div class="danger-box">
            <h3>⚠️ TIMING ATTACK PARTIALLY SUCCESSFUL!</h3>
            <strong>Extracted Information:</strong> ~{extracted_bits} key bits<br>
            <strong>Total Key Size:</strong> {key_size_bits} bits<br>
            <strong>Recovery Progress:</strong> {progress_pct:.3f}%<br>
            <br>
            <strong>🔍 Attack Method:</strong><br>
            1. Measure cryptographic operation timing repeatedly<br>
            2. Perform statistical correlation with inputs/outputs<br>
            3. Use differential analysis to extract key bits<br>
            4. With enough measurements, full key recovery possible<br>
            <br>
            <strong>⏱️ Why Timing Varies:</strong><br>
            • Conditional branches based on secret data<br>
            • Cache access patterns<br>
            • Memory access times<br>
            • CPU pipeline effects<br>
            • All leak information about secret keys!
            </div>
            """, unsafe_allow_html=True)
        
        # Show vulnerable code example
        st.markdown("---")
        st.markdown("### 🐛 Vulnerable vs Secure Implementation")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**❌ Vulnerable Code:**")
            st.code("""
# Variable-time signature verification
def verify_signature_INSECURE(sig, expected):
    for i in range(len(sig)):
        if sig[i] != expected[i]:
            return False  # ← Early exit!
        # Time varies based on mismatch location
    return True

# Problem:
# - Mismatch at byte 0: returns in ~1µs
# - Mismatch at byte 100: returns in ~100µs
# - Attacker learns: "First 100 bytes correct!"
            """, language="python")
        
        with col2:
            st.markdown("**✅ Secure Code:**")
            st.code("""
# Constant-time signature verification
def verify_signature_SECURE(sig, expected):
    result = 0
    for i in range(len(sig)):
        result |= sig[i] ^ expected[i]
        # Always executes same number of iterations
    return result == 0  # Single comparison at end

# Properties:
# - Always processes all bytes
# - No early exit regardless of input
# - Constant execution time
# - No timing leak
            """, language="python")
        
        # Attack success vs measurements
        st.markdown("---")
        st.markdown("### 📊 Attack Success Rate")
        
        samples = [100, 500, 1000, 2000, 5000, 10000]
        bits = [int(s * 0.5 / 100) for s in samples]
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=samples,
            y=bits,
            mode='lines+markers',
            name='Bits Extracted',
            line=dict(color='red', width=3),
            marker=dict(size=10)
        ))
        
        fig.update_layout(
            title='Key Bits Extracted vs Number of Measurements',
            xaxis_title='Number of Timing Measurements',
            yaxis_title='Key Bits Recovered',
            xaxis_type='log',
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Defense mechanisms
        st.markdown("---")
        st.markdown("### 🛡️ Defense Mechanisms")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            **Software Countermeasures:**
            
            **1. Constant-Time Algorithms:**
            ```python
            # No data-dependent branches
            # No data-dependent memory access
            # Fixed execution path
            ```
            
            **2. Blinding:**
            ```python
            def sign_with_blinding(message, key):
                blind = random()
                blinded_key = key + blind
                signature = sign(message, blinded_key)
                return unblind(signature, blind)
            ```
            
            **3. Algorithmic Noise:**
            ```python
            # Add random delays
            random_delay(0, max_delay)
            perform_crypto_operation()
            ```
            """)
        
        with col2:
            st.markdown("""
            **Hardware Countermeasures:**
            
            **1. Secure Enclaves:**
            - Intel SGX
            - ARM TrustZone
            - Isolated execution environment
            
            **2. Hardware Random Number Generators:**
            - True randomness for blinding
            - Unpredictable timing variations
            
            **3. Constant-Time Instructions:**
            - CPU instructions with fixed timing
            - No cache-based timing variations
            
            **4. Physical Isolation:**
            - Hardware Security Modules (HSM)
            - Tamper-resistant devices
            """)
        
        st.success("""
        **Critical Lesson:** Even mathematically secure algorithms can be broken through 
        implementation side-channels. Secure systems require:
        
        1. ✓ Strong cryptographic algorithms (Kyber768, Dilithium3)
        2. ✓ **Constant-time implementations** ← ESSENTIAL!
        3. ✓ Hardware security features
        4. ✓ Regular security audits
        5. ✓ Defense in depth
        
        **Real-world impact:** Timing attacks have successfully broken:
        - RSA implementations (Kocher, 1996)
        - AES implementations (Bernstein, 2005)
        - TLS/SSL servers (Lucky13, 2013)
        
        Always use audited, constant-time cryptographic libraries!
        """)
        
        # Log attack
        self.logger.log_attack({
            'attack_name': 'Timing Side-Channel Attack',
            'attack_type': 'Protocol/Implementation',
            'success': True,
            'measurements': num_measurements,
            'bits_extracted': extracted_bits,
            'progress_percent': progress_pct,
            'lesson': 'Constant-time implementation required for all crypto operations'
        })