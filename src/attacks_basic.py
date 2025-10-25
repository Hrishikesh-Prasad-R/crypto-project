"""Complete Attack Simulations for Post-Quantum Cryptography Demo
Shows both successful and failed attacks with visual feedback

FILE: attacks.py
Save this as a separate file and import in your main Streamlit app
"""

import streamlit as st
import time
import random
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
import pandas as pd


def attack_simulations_page():
    """Main attack simulations page - ENTRY POINT"""
    st.header("⚔️ Attack Simulations")
    
    # Check if keys are generated
    if not st.session_state.alice_keys or not st.session_state.bob_keys:
        st.warning("⚠️ Please generate keys first in the Key Generation page!")
        return
    
    # Initialize attack statistics
    if 'attack_stats' not in st.session_state:
        st.session_state.attack_stats = {
            'total_attacks': 0,
            'successful_attacks': 0,
            'failed_attacks': 0,
            'attack_history': []
        }
    
    # Header with stats dashboard
    st.markdown("### 📊 Attack Statistics Dashboard")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Attacks Simulated", 
                 st.session_state.attack_stats['total_attacks'],
                 help="Total number of attacks run")
    with col2:
        st.metric("Successful Attacks", 
                 st.session_state.attack_stats['successful_attacks'],
                 delta="⚠️ Vulnerabilities", 
                 delta_color="inverse")
    with col3:
        st.metric("Blocked Attacks", 
                 st.session_state.attack_stats['failed_attacks'],
                 delta="✓ Protected", 
                 delta_color="normal")
    
    st.markdown("---")
    
    # Info box
    st.markdown("""
    <div class="info-box">
        <strong>🎓 Educational Security Demonstration</strong><br>
        Explore both successful and failed attacks to understand how post-quantum 
        cryptography protects communications and where additional protections are needed.
    </div>
    """, unsafe_allow_html=True)
    
    # Main navigation
    attack_category = st.radio(
        "**Choose Attack Category:**",
        ["🛡️ Cryptographically Protected (Attacks FAIL)", 
         "⚠️ Protocol-Level Vulnerabilities (Attacks SUCCEED)",
         "📊 Comparative Analysis"],
        horizontal=True
    )
    
    st.markdown("---")
    
    # Route to appropriate section
    if attack_category == "🛡️ Cryptographically Protected (Attacks FAIL)":
        failed_attacks_section()
    elif attack_category == "⚠️ Protocol-Level Vulnerabilities (Attacks SUCCEED)":
        successful_attacks_section()
    else:
        comparative_analysis_section()


# ============= SECTION 1: FAILED ATTACKS =============

def failed_attacks_section():
    """Attacks that fail due to cryptographic protections"""
    
    st.subheader("🛡️ Cryptographically Protected Attacks")
    st.info("These attacks fail because the cryptographic algorithms detect and prevent them.")
    
    attack_type = st.selectbox(
        "**Select Attack to Simulate:**",
        ["Message Tampering", 
         "Signature Forgery",
         "Brute Force Key Recovery",
         "Ciphertext Manipulation"]
    )
    
    if attack_type == "Message Tampering":
        tampering_attack_fails()
    elif attack_type == "Signature Forgery":
        forgery_attack_fails()
    elif attack_type == "Brute Force Key Recovery":
        brute_force_attack_fails()
    elif attack_type == "Ciphertext Manipulation":
        ciphertext_attack_fails()


def tampering_attack_fails():
    """Message Tampering - FAILS due to signature verification"""
    st.markdown("### ✂️ Message Tampering Attack")
    
    # Visual flow
    st.markdown("**Attack Flow:**")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown("**👩 Alice**<br>Sends message", unsafe_allow_html=True)
    with col2:
        st.markdown("**📤 →**<br>Encrypted", unsafe_allow_html=True)
    with col3:
        st.markdown("**🕵️ Eve**<br>Tampers", unsafe_allow_html=True)
    with col4:
        st.markdown("**👨 Bob**<br>❌ Rejects", unsafe_allow_html=True)
    
    st.markdown("---")
    
    message = st.text_input("Alice's message:", "Transfer $100 to Alice", key="tamper_msg")
    
    col1, col2 = st.columns(2)
    with col1:
        tamper_location = st.selectbox("Tamper with:", 
            ["Encrypted Message", "Signature", "Both"])
    with col2:
        tamper_amount = st.slider("Corruption intensity (bits):", 1, 50, 10)
    
    if st.button("🚀 Launch Tampering Attack", type="primary", key="tamper_btn"):
        with st.spinner("Executing attack..."):
            
            # Step 1: Encrypt
            st.write("**Step 1:** Alice encrypts and signs message")
            package = st.session_state.channel.send_message(
                message,
                st.session_state.bob_keys['kem_public'],
                st.session_state.alice_keys['sign_secret']
            )
            time.sleep(0.3)
            st.success("✓ Message encrypted and signed")
            
            # Step 2: Tamper
            st.write("**Step 2:** 🕵️ Attacker intercepts and tampers")
            tampered_package = package.copy()
            
            if tamper_location in ["Encrypted Message", "Both"]:
                msg_bytes = bytearray(package['encrypted_message'])
                for _ in range(tamper_amount):
                    pos = random.randint(0, len(msg_bytes) - 1)
                    msg_bytes[pos] ^= random.randint(1, 255)
                tampered_package['encrypted_message'] = bytes(msg_bytes)
                st.warning(f"⚠️ Flipped {tamper_amount} bits in encrypted message")
            
            if tamper_location in ["Signature", "Both"]:
                sig_bytes = bytearray(package['signature'])
                for _ in range(tamper_amount):
                    pos = random.randint(0, len(sig_bytes) - 1)
                    sig_bytes[pos] ^= random.randint(1, 255)
                tampered_package['signature'] = bytes(sig_bytes)
                st.warning(f"⚠️ Flipped {tamper_amount} bits in signature")
            
            time.sleep(0.3)
            
            # Step 3: Verify
            st.write("**Step 3:** 👨 Bob verifies signature")
            try:
                decrypted = st.session_state.channel.receive_message(
                    tampered_package,
                    st.session_state.bob_keys['kem_secret'],
                    st.session_state.alice_keys['sign_public']
                )
                st.error("❌ This should never happen - tampering was not detected!")
            except Exception as e:
                st.markdown(f"""
                <div class="danger-box">
                    <h3>❌ ATTACK BLOCKED!</h3>
                    <strong>Bob's system detected tampering!</strong><br>
                    <br>
                    🛡️ <strong>Protection:</strong> Dilithium3 Digital Signatures<br>
                    🔒 <strong>Result:</strong> Message rejected<br>
                    <br>
                    <strong>Technical:</strong> Signature verification failed because the message 
                    was modified after signing. This proves authenticity and integrity.
                </div>
                """, unsafe_allow_html=True)
                
                update_attack_stats({
                    'attack_name': 'Message Tampering',
                    'success': False,
                    'protection': 'Dilithium3 Digital Signatures'
                })


def forgery_attack_fails():
    """Signature Forgery - FAILS due to mathematical impossibility"""
    st.markdown("### 🎭 Signature Forgery Attack")
    
    st.write("""
    **Scenario:** Attacker tries to create a valid signature without Alice's private key.
    """)
    
    fake_message = st.text_input("Attacker's fake message:", 
        "Transfer $10,000 to attacker", key="forge_msg")
    
    forgery_method = st.radio(
        "Forgery technique:",
        ["Random Signature", "Reuse Old Signature", "Mathematical Crafting"],
        key="forge_method"
    )
    
    if st.button("🚀 Attempt Signature Forgery", type="primary", key="forge_btn"):
        with st.spinner("Attempting forgery..."):
            
            st.write("**Step 1:** 🕵️ Attacker creates fake message")
            st.warning(f"⚠️ Fake message: '{fake_message}'")
            time.sleep(0.3)
            
            st.write("**Step 2:** 🕵️ Attacker generates fake signature")
            
            # Create legitimate package first
            real_package = st.session_state.channel.send_message(
                fake_message,
                st.session_state.bob_keys['kem_public'],
                st.session_state.alice_keys['sign_secret']
            )
            
            forged_package = real_package.copy()
            
            if forgery_method == "Random Signature":
                forged_package['signature'] = bytes(random.randint(0, 255) for _ in range(3309))
                st.info("Generated random bytes as signature")
            elif forgery_method == "Reuse Old Signature":
                old_package = st.session_state.channel.send_message(
                    "Different message",
                    st.session_state.bob_keys['kem_public'],
                    st.session_state.alice_keys['sign_secret']
                )
                forged_package['signature'] = old_package['signature']
                st.info("Copied signature from different message")
            else:
                sig_bytes = bytearray(real_package['signature'])
                for i in range(0, len(sig_bytes), 100):
                    sig_bytes[i] ^= 0xFF
                forged_package['signature'] = bytes(sig_bytes)
                st.info("Modified signature mathematically")
            
            time.sleep(0.3)
            
            st.write("**Step 3:** 👨 Bob verifies the signature")
            try:
                decrypted = st.session_state.channel.receive_message(
                    forged_package,
                    st.session_state.bob_keys['kem_secret'],
                    st.session_state.alice_keys['sign_public']
                )
                st.error("❌ Forgery succeeded - this should not happen!")
            except ValueError:
                st.markdown("""
                <div class="danger-box">
                    <h3>❌ FORGERY DETECTED!</h3>
                    <strong>Signature verification FAILED!</strong><br>
                    <br>
                    🛡️ <strong>Protection:</strong> Lattice-based cryptography (Dilithium3)<br>
                    🔒 <strong>Security:</strong> Computationally impossible to forge<br>
                    <br>
                    <strong>Why forgery is impossible:</strong><br>
                    • Requires solving hard lattice problems<br>
                    • Probability of success: ~2^-128 (essentially zero)<br>
                    • Even quantum computers cannot forge signatures<br>
                    • Only Alice's private key can create valid signatures
                </div>
                """, unsafe_allow_html=True)
                
                update_attack_stats({
                    'attack_name': 'Signature Forgery',
                    'success': False,
                    'protection': 'Dilithium3 Lattice Cryptography'
                })


def brute_force_attack_fails():
    """Brute Force - FAILS due to massive key space"""
    st.markdown("### 💪 Brute Force Key Recovery Attack")
    
    st.write("""
    **Scenario:** Attacker tries all possible keys until finding the correct one.
    """)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🔐 Kyber768 Security")
        st.write("**Key space:** 2^254 possible keys")
        st.write("**Security level:** AES-192 equivalent")
        st.write("**Quantum resistant:** ✓ Yes")
    
    with col2:
        st.markdown("#### ⏱️ Attack Feasibility")
        st.write("**Classical computer:** Never")
        st.write("**All Earth's computers:** Never")
        st.write("**Quantum computer:** Still secure!")
    
    computing_power = st.select_slider(
        "Attacker's computing power:",
        options=["1 PC", "1,000 PCs", "Supercomputer", "All Earth's Computers", "Quantum Computer"],
        value="Supercomputer"
    )
    
    if st.button("🚀 Calculate Break Time", type="primary", key="brute_btn"):
        with st.spinner("Calculating..."):
            time.sleep(0.5)
            
            ops_per_second = {
                "1 PC": 1e9,
                "1,000 PCs": 1e12,
                "Supercomputer": 1e18,
                "All Earth's Computers": 1e21,
                "Quantum Computer": 1e15
            }
            
            ops = ops_per_second[computing_power]
            total_keys = 2**254
            seconds = total_keys / ops
            years = seconds / (365.25 * 24 * 3600)
            universe_age = 13.8e9
            universes = years / universe_age
            
            st.markdown(f"""
            <div class="danger-box">
                <h3>❌ ATTACK IMPOSSIBLE!</h3>
                <strong>Computing Power:</strong> {computing_power}<br>
                <strong>Operations per second:</strong> {ops:.2e}<br>
                <strong>Total keys to try:</strong> 2^254 ≈ {total_keys:.2e}<br>
                <strong>Time required:</strong> {universes:.2e} × Age of Universe<br>
                <br>
                🛡️ <strong>Protection:</strong> Massive key space makes brute force impossible<br>
                Even with {computing_power}, the attack would take longer than the universe has existed!
            </div>
            """, unsafe_allow_html=True)
            
            # Visualization
            fig = go.Figure()
            
            algorithms = ['DES\n(Broken)', 'AES-128', 'RSA-2048\n(Quantum vulnerable)', 'AES-256', 'Kyber768\n(PQC)']
            security_bits = [56, 128, 112, 256, 254]
            colors = ['red', 'orange', 'yellow', 'lightgreen', 'green']
            
            fig.add_trace(go.Bar(
                x=algorithms,
                y=security_bits,
                marker_color=colors,
                text=[f"2^{b} keys" for b in security_bits],
                textposition='auto',
            ))
            
            fig.add_hline(y=128, line_dash="dash", line_color="red",
                          annotation_text="Minimum Security (2^128)")
            
            fig.update_layout(
                title='Security Level Comparison',
                xaxis_title='Algorithm',
                yaxis_title='Security Bits',
                yaxis_type='log',
                showlegend=False,
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            update_attack_stats({
                'attack_name': 'Brute Force',
                'success': False,
                'protection': 'Large Key Space (2^254)'
            })


def ciphertext_attack_fails():
    """Ciphertext-only attack - FAILS"""
    st.markdown("### 🔍 Ciphertext-Only Attack")
    
    st.write("""
    **Scenario:** Attacker has ciphertext but no key. Can they decrypt it?
    """)
    
    message = st.text_input("Secret message:", "The password is: SecretPass123", key="cipher_msg")
    
    if st.button("🚀 Encrypt & Attack", type="primary", key="cipher_btn"):
        with st.spinner("Encrypting..."):
            
            # Encrypt
            package = st.session_state.channel.send_message(
                message,
                st.session_state.bob_keys['kem_public'],
                st.session_state.alice_keys['sign_secret']
            )
            
            st.markdown("### 🕵️ Attacker's View:")
            
            col1, col2 = st.columns(2)
            with col1:
                st.write("**What attacker has:**")
                st.code(package['encrypted_message'].hex()[:200] + "...")
                st.write(f"✓ Ciphertext ({len(package['encrypted_message'])} bytes)")
                st.write(f"✓ Algorithm known (AES-256-GCM)")
            
            with col2:
                st.write("**What attacker needs:**")
                st.write("✗ Encryption key (unknown)")
                st.write("✗ Nonce (included but useless without key)")
                st.write("✗ Plaintext (that's what they want!)")
            
            st.markdown("### 🔓 Attack Attempts:")
            
            with st.spinner("Trying frequency analysis..."):
                time.sleep(0.5)
                st.error("❌ Failed: Modern encryption eliminates statistical patterns")
            
            with st.spinner("Trying known-plaintext attack..."):
                time.sleep(0.5)
                st.error("❌ Failed: AES-256-GCM is secure against known-plaintext")
            
            with st.spinner("Trying cryptanalysis..."):
                time.sleep(0.5)
                st.error("❌ Failed: No known attacks against AES-256-GCM")
            
            st.markdown("""
            <div class="danger-box">
                <h3>❌ ALL ATTACKS FAILED!</h3>
                <strong>Protection:</strong> AES-256-GCM authenticated encryption<br>
                <strong>Security:</strong> No practical attacks known<br>
                <strong>Key strength:</strong> 2^256 possible keys<br>
                <br>
                🛡️ Without the encryption key, the ciphertext is completely unreadable.<br>
                The attacker cannot recover any information about the plaintext.
            </div>
            """, unsafe_allow_html=True)
            
            update_attack_stats({
                'attack_name': 'Ciphertext-Only Attack',
                'success': False,
                'protection': 'AES-256-GCM Encryption'
            })


# ============= SECTION 2: SUCCESSFUL ATTACKS =============

def successful_attacks_section():
    """Attacks that succeed - shows need for protocol-level security"""
    
    st.subheader("⚠️ Protocol-Level Vulnerabilities")
    st.warning("⚠️ These attacks SUCCEED even with strong cryptography! Shows why multiple security layers are needed.")
    
    attack_type = st.selectbox(
        "**Select Attack to Simulate:**",
        ["Replay Attack",
         "Man-in-the-Middle (No Key Authentication)",
         "Downgrade Attack",
         "Side-Channel Timing Attack"]
    )
    
    if attack_type == "Replay Attack":
        replay_attack_succeeds()
    elif attack_type == "Man-in-the-Middle (No Key Authentication)":
        mitm_attack_succeeds()
    elif attack_type == "Downgrade Attack":
        downgrade_attack_succeeds()
    elif attack_type == "Side-Channel Timing Attack":
        timing_attack_succeeds()


def replay_attack_succeeds():
    """Replay Attack - SUCCEEDS without nonce tracking"""
    st.markdown("### 🔄 Replay Attack")
    
    st.markdown("""
    <div class="danger-box">
        <strong>⚠️ Expected Result: ATTACK SUCCEEDS</strong><br>
        Cryptographically valid messages can be replayed without timestamp/nonce validation.
    </div>
    """, unsafe_allow_html=True)
    
    if 'replay_messages' not in st.session_state:
        st.session_state.replay_messages = []
    
    message = st.text_input("Transaction message:", "Transfer $500 to Alice", key="replay_msg")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📤 Send Transaction", key="replay_send"):
            package = st.session_state.channel.send_message(
                message,
                st.session_state.bob_keys['kem_public'],
                st.session_state.alice_keys['sign_secret']
            )
            
            st.session_state.replay_messages.append({
                'package': package,
                'message': message,
                'timestamp': time.time()
            })
            
            st.success(f"✓ Transaction sent at {time.strftime('%H:%M:%S')}")
            st.info("🕵️ Attacker captured the message!")
    
    with col2:
        if st.button("🔄 Replay Message", key="replay_attack") and st.session_state.replay_messages:
            old_msg = st.session_state.replay_messages[-1]
            age = time.time() - old_msg['timestamp']
            
            st.warning(f"⚠️ Replaying message from {age:.1f} seconds ago...")
            
            try:
                decrypted = st.session_state.channel.receive_message(
                    old_msg['package'],
                    st.session_state.bob_keys['kem_secret'],
                    st.session_state.alice_keys['sign_public']
                )
                
                st.markdown(f"""
                <div class="danger-box">
                    <h3>✓ ATTACK SUCCESSFUL!</h3>
                    <strong>Message:</strong> "{decrypted}"<br>
                    <strong>Signature:</strong> ✓ Valid (authentic)<br>
                    <strong>Encryption:</strong> ✓ Correct<br>
                    <br>
                    ⚠️ <strong>Impact:</strong> Transaction executed TWICE!<br>
                    💰 Alice charged $500 again!
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown("### 🛡️ Required Defenses:")
                st.info("""
                **Cryptography cannot prevent replay attacks!** Need protocol-level protections:
                - ✓ **Timestamps:** Reject messages older than X seconds
                - ✓ **Nonce tracking:** Store used nonces in database
                - ✓ **Sequence numbers:** Maintain message ordering
                - ✓ **Session tokens:** One-time use only
                """)
                
                update_attack_stats({
                    'attack_name': 'Replay Attack',
                    'success': True,
                    'lesson': 'Protocol-level protection needed'
                })
                
            except Exception as e:
                st.error(f"Error: {e}")
    
    if st.session_state.replay_messages:
        st.markdown("---")
        st.write(f"**📋 Captured Messages: {len(st.session_state.replay_messages)}**")
        for i, msg in enumerate(st.session_state.replay_messages[-3:], 1):
            age = time.time() - msg['timestamp']
            st.text(f"{i}. '{msg['message']}' ({age:.1f}s ago)")


def mitm_attack_succeeds():
    """MITM - SUCCEEDS without PKI"""
    st.markdown("### 🕵️ Man-in-the-Middle Attack")
    
    st.markdown("""
    <div class="danger-box">
        <strong>⚠️ Expected Result: PARTIAL SUCCESS</strong><br>
        Without public key authentication (PKI/certificates), attacker can substitute their own keys.
    </div>
    """, unsafe_allow_html=True)
    
    message = st.text_input("Alice's message:", "Meet at the secret location", key="mitm_msg")
    
    if st.button("🚀 Simulate MITM Attack", type="primary", key="mitm_btn"):
        with st.spinner("Executing multi-stage attack..."):
            
            # Step 1
            st.write("**Step 1:** 🕵️ Eve generates malicious keys")
            eve_keys = st.session_state.channel.generate_keys()
            time.sleep(0.4)
            st.success("✓ Eve has her own key pair")
            
            # Step 2
            st.write("**Step 2:** 👩 Alice encrypts (using Eve's key by mistake)")
            st.warning("⚠️ Alice thinks she's using Bob's key, but Eve substituted hers!")
            
            package_to_eve = st.session_state.channel.send_message(
                message,
                eve_keys['kem_public'],  # Wrong key!
                st.session_state.alice_keys['sign_secret']
            )
            time.sleep(0.4)
            st.info("Message encrypted with Eve's public key")
            
            # Step 3
            st.write("**Step 3:** 🕵️ Eve intercepts and decrypts")
            try:
                decrypted_by_eve = st.session_state.channel.receive_message(
                    package_to_eve,
                    eve_keys['kem_secret'],
                    st.session_state.alice_keys['sign_public']
                )
                
                st.markdown(f"""
                <div class="danger-box">
                    <h3>✓ EVE READ THE MESSAGE!</h3>
                    <strong>Decrypted:</strong> "{decrypted_by_eve}"<br>
                    <strong>Signature:</strong> ✓ Valid from Alice<br>
                    <br>
                    🕵️ <strong>Success:</strong> Eve knows Alice's secret!
                </div>
                """, unsafe_allow_html=True)
                
                # Step 4
                st.write("**Step 4:** 🕵️ Eve tries to forward to Bob")
                st.info("But Eve cannot forge Alice's signature...")
                
                package_to_bob = st.session_state.channel.send_message(
                    decrypted_by_eve,
                    st.session_state.bob_keys['kem_public'],
                    eve_keys['sign_secret']  # Eve's signature!
                )
                
                st.write("**Step 5:** 👨 Bob verifies")
                try:
                    st.session_state.channel.receive_message(
                        package_to_bob,
                        st.session_state.bob_keys['kem_secret'],
                        st.session_state.alice_keys['sign_public']
                    )
                except:
                    st.success("✓ Bob detected forged signature!")
                
                st.markdown("---")
                st.markdown("### 📊 Attack Analysis")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("""
                    **✓ What Worked:**
                    - Eve intercepted message
                    - Eve read Alice's secret
                    - Key substitution succeeded
                    """)
                
                with col2:
                    st.markdown("""
                    **✗ What Failed:**
                    - Eve cannot forge signatures
                    - Bob detected the forgery
                    - Attack was detected
                    """)
                
                st.success("""
                ### 🛡️ Complete Defense:
                **Multiple layers needed:**
                1. ✓ Encryption (prevents eavesdropping)
                2. ✓ Digital Signatures (prevents forgery) ← Already have this!
                3. ✓ **Public Key Infrastructure (PKI)** ← MISSING - needed to verify key ownership
                4. ✓ Certificate Authorities (like TLS/SSL)
                
                **Lesson:** Strong crypto isn't enough. Must also authenticate public keys!
                """)
                
                update_attack_stats({
                    'attack_name': 'MITM Attack',
                    'success': True,
                    'lesson': 'PKI needed for key authentication'
                })
                
            except Exception as e:
                st.error(f"Error: {e}")


def downgrade_attack_succeeds():
    """Downgrade Attack - SUCCEEDS without protocol enforcement"""
    st.markdown("### 📉 Downgrade Attack")
    
    st.markdown("""
    <div class="danger-box">
        <strong>⚠️ Expected Result: ATTACK SUCCEEDS</strong><br>
        Attacker forces use of weak classical crypto instead of post-quantum.
    </div>
    """, unsafe_allow_html=True)
    
    st.write("""
    **Scenario:** Attacker intercepts key negotiation and removes PQC options,
    forcing vulnerable RSA-2048 instead of quantum-resistant Kyber768.
    """)
    
    message = st.text_input("Confidential message:", "Product launch: March 15, 2026", key="down_msg")
    
    if st.button("🚀 Simulate Downgrade Attack", type="primary", key="down_btn"):
        
        st.markdown("### Step 1: Normal Negotiation")
        with st.spinner("Negotiating..."):
            time.sleep(0.5)
            st.info("""
            **Alice proposes:** Kyber768, Dilithium3, RSA-4096, RSA-2048  
            **Bob supports:** Kyber768, Dilithium3, RSA-4096, RSA-2048  
            **Expected:** Use strongest available (Kyber768)
            """)
        
        st.markdown("### Step 2: 🕵️ Attacker Interferes")
        with st.spinner("Eve modifying negotiation..."):
            time.sleep(0.5)
            st.warning("⚠️ Eve removes post-quantum options!")
            st.code("""
# What Bob receives (modified by Eve):
Supported: RSA-2048 only

# What actually happened:
Alice sent: Kyber768, Dilithium3, RSA-4096, RSA-2048
Eve stripped: Kyber768, Dilithium3, RSA-4096
            """)
        
        st.markdown("### Step 3: ✓ Downgrade Successful")
        st.markdown("""
        <div class="danger-box">
            <h3>⚠️ ATTACK SUCCEEDED!</h3>
            <strong>Result:</strong> Communication uses RSA-2048<br>
            <strong>Impact:</strong> Vulnerable to future quantum attacks<br>
            <br>
            🕵️ <strong>Attacker's strategy: "Harvest now, decrypt later"</strong><br>
            • Records encrypted traffic today<br>
            • Waits for quantum computers (~2030)<br>
            • Decrypts everything retroactively<br>
            • Alice's 2026 product launch exposed in 2031!
        </div>
        """, unsafe_allow_html=True)
        
        # Comparison chart
        st.markdown("### 📊 Security Comparison")
        
        fig = go.Figure()
        
        categories = ['Key Exchange', 'Digital Signature', 'Quantum Resistant', 'Future Proof']
        
        fig.add_trace(go.Scatterpolar(
            r=[100, 100, 100, 100],
            theta=categories,
            fill='toself',
            name='Kyber768 + Dilithium3',
            line_color='green'
        ))
        
        fig.add_trace(go.Scatterpolar(
            r=[70, 70, 0, 0],
            theta=categories,
            fill='toself',
            name='RSA-2048 (Downgraded)',
            line_color='red'
        ))
        
        fig.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
            showlegend=True,
            title="Security Level: PQC vs Classical"
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        st.success("""
        ### 🛡️ Defense Against Downgrade:
        **Required protections:**
        1. ✓ **Strict TLS policy** (require minimum version)
        2. ✓ **Signed negotiation** (prevent tampering)
        3. ✓ **HSTS-like enforcement** (force PQC when available)
        4. ✓ **Certificate transparency** (detect MITM)
        
        **Best practice:** Reject connections without post-quantum support!
        """)
        
        update_attack_stats({
            'attack_name': 'Downgrade Attack',
            'success': True,
            'lesson': 'Strict protocol enforcement needed'
        })


def timing_attack_succeeds():
    """Timing Attack - SUCCEEDS without constant-time implementation"""
    st.markdown("### ⏱️ Side-Channel Timing Attack")
    
    st.markdown("""
    <div class="danger-box">
        <strong>⚠️ Expected Result: ATTACK SUCCEEDS</strong><br>
        Measuring execution time can leak secret key information.
    </div>
    """, unsafe_allow_html=True)
    
    st.write("""
    **Scenario:** Attacker measures cryptographic operation timing to extract key bits.
    """)
    
    num_measurements = st.slider("Timing measurements:", 100, 5000, 1000, step=100, key="timing_slider")
    
    if st.button("🚀 Launch Timing Attack", type="primary", key="timing_btn"):
        
        st.markdown("### Step 1: Collecting Timing Data")
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        timing_data = []
        
        for i in range(num_measurements):
            if i % 100 == 0:
                status_text.text(f"Measurements: {i}/{num_measurements}")
                progress_bar.progress(i / num_measurements)
            
            # Simulate timing variations (real attacks exploit actual timing differences)
            base_time = 0.5
            variation = random.gauss(0, 0.1)
            secret_dependent = random.uniform(-0.05, 0.05)
            timing_data.append(base_time + variation + secret_dependent)
        
        progress_bar.progress(1.0)
        status_text.text(f"✓ Collected {num_measurements} measurements")
        
        st.markdown("### Step 2: Statistical Analysis")
        
        timings = np.array(timing_data)
        mean_time = np.mean(timings)
        std_time = np.std(timings)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Mean Time", f"{mean_time:.3f} ms")
        with col2:
            st.metric("Std Deviation", f"{std_time:.3f} ms")
        with col3:
            st.metric("Samples", num_measurements)
        
        # Histogram
        fig = go.Figure()
        fig.add_trace(go.Histogram(
            x=timings,
            nbinsx=50,
            name='Timing Distribution',
            marker_color='red'
        ))
        
        fig.update_layout(
            title='Timing Measurements Distribution',
            xaxis_title='Execution Time (ms)',
            yaxis_title='Frequency'
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("### Step 3: Key Extraction")
        
        with st.spinner("Applying statistical correlation..."):
            time.sleep(1)
            
            # More samples = more bits extracted
            extracted_bits = min(64, num_measurements // 100)
            key_size_bits = 2400 * 8  # Kyber768 secret key in bits
            progress_pct = (extracted_bits / key_size_bits) * 100
            
            st.markdown(f"""
            <div class="danger-box">
                <h3>⚠️ ATTACK PARTIALLY SUCCESSFUL!</h3>
                <strong>Key bits extracted:</strong> ~{extracted_bits} bits<br>
                <strong>Total key size:</strong> {key_size_bits} bits<br>
                <strong>Progress:</strong> {progress_pct:.2f}% of key recovered<br>
                <br>
                🕵️ <strong>Attack method:</strong><br>
                • Measure operation timing repeatedly<br>
                • Correlate timing with input/output<br>
                • Use statistical methods to extract key bits<br>
                • Given enough measurements, full key recovery possible
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("### 🔍 Why This Works")
        
        st.code("""
# Vulnerable code example:
def verify_signature(signature, expected):
    for i in range(len(signature)):
        if signature[i] != expected[i]:
            return False  # Early exit = timing leak!
    return True

# Problem:
# - Wrong at byte 0: Returns in ~1µs
# - Wrong at byte 100: Returns in ~100µs
# - Attacker learns: "First 100 bytes are correct!"
        """, language="python")
        
        st.markdown("### 🛡️ Defenses")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            **Software Solutions:**
            - ✓ Constant-time algorithms
            - ✓ No conditional branches on secrets
            - ✓ Blinding techniques
            - ✓ Fixed execution time
            """)
        
        with col2:
            st.markdown("""
            **Hardware Solutions:**
            - ✓ Random delays
            - ✓ Noise injection
            - ✓ Secure enclaves
            - ✓ Physical isolation
            """)
        
        # Attack success vs measurements
        fig2 = go.Figure()
        
        samples = [100, 500, 1000, 2000, 5000]
        bits = [s // 100 for s in samples]
        
        fig2.add_trace(go.Scatter(
            x=samples,
            y=bits,
            mode='lines+markers',
            name='Bits Extracted',
            line=dict(color='red', width=3)
        ))
        
        fig2.update_layout(
            title='Attack Success vs Measurements',
            xaxis_title='Number of Measurements',
            yaxis_title='Key Bits Recovered',
            xaxis_type='log'
        )
        
        st.plotly_chart(fig2, use_container_width=True)
        
        st.success("""
        **Critical Lesson:** Even perfect cryptographic algorithms can leak information 
        through implementation details. Always use audited, constant-time implementations!
        """)
        
        update_attack_stats({
            'attack_name': 'Timing Side-Channel',
            'success': True,
            'bits_extracted': extracted_bits,
            'lesson': 'Constant-time implementation required'
        })


# ============= SECTION 3: COMPARATIVE ANALYSIS =============

def comparative_analysis_section():
    """Compare different scenarios"""
    st.subheader("📊 Comparative Security Analysis")
    
    analysis_type = st.selectbox(
        "Choose analysis:",
        ["Attack Success Matrix",
         "Classical vs Post-Quantum",
         "Defense Layers Visualization"]
    )
    
    if analysis_type == "Attack Success Matrix":
        attack_matrix_analysis()
    elif analysis_type == "Classical vs Post-Quantum":
        classical_vs_pqc_analysis()
    elif analysis_type == "Defense Layers Visualization":
        defense_layers_analysis()


def attack_matrix_analysis():
    """Attack success matrix"""
    st.markdown("### 🎯 Attack Success Matrix")
    
    st.write("Shows which attacks succeed (✓) or fail (✗) against different security measures:")
    
    matrix_data = {
        'Attack Type': [
            "Message Tampering",
            "Signature Forgery",
            "Brute Force",
            "Ciphertext Attack",
            "Replay Attack",
            "MITM (No PKI)",
            "Downgrade Attack",
            "Timing Attack"
        ],
        'No Crypto': ['✓', '✓', '✓', '✓', '✓', '✓', '✓', '✓'],
        'Classical\nCrypto': ['✗', '✗', '✗', '✗', '✓', '✓', '✓', '✓'],
        'Post-Quantum\nCrypto': ['✗', '✗', '✗', '✗', '✓', '✓', '✓', '✓'],
        'PQC + PKI': ['✗', '✗', '✗', '✗', '✓', '✗', '✓', '✓'],
        'PQC + PKI +\nNonce': ['✗', '✗', '✗', '✗', '✗', '✗', '✗', '✓'],
        'Complete\nSolution': ['✗', '✗', '✗', '✗', '✗', '✗', '✗', '✗']
    }
    
    df = pd.DataFrame(matrix_data)
    
    # Style the dataframe
    def style_cell(val):
        if val == '✓':
            return 'background-color: #ff6b6b; color: white; font-weight: bold; font-size: 18px;'
        elif val == '✗':
            return 'background-color: #51cf66; color: white; font-weight: bold; font-size: 18px;'
        return ''
    
    styled_df = df.style.applymap(style_cell, subset=df.columns[1:])
    
    st.dataframe(styled_df, use_container_width=True, height=400)
    
    st.markdown("""
    **Key Insights:**
    - 🔐 Post-quantum crypto alone blocks only 4/8 attacks (50%)
    - 🛡️ Multiple defense layers required for complete security
    - ⚠️ Timing attacks need hardware/software countermeasures
    - ✓ Complete solution requires: PQC + PKI + Nonce tracking + Constant-time implementation
    """)
    
    # Bar chart
    systems = list(matrix_data.keys())[1:]
    blocked = [col.count('✗') for col in [matrix_data[sys] for sys in systems]]
    
    fig = go.Figure()
    
    colors = ['red', 'orange', 'yellow', 'lightgreen', 'green', 'darkgreen']
    
    fig.add_trace(go.Bar(
        x=systems,
        y=blocked,
        marker_color=colors,
        text=blocked,
        texttemplate='%{text}/8 attacks blocked',
        textposition='auto',
    ))
    
    fig.update_layout(
        title='Security Effectiveness by System',
        xaxis_title='Security System',
        yaxis_title='Attacks Blocked (out of 8)',
        yaxis_range=[0, 8],
        showlegend=False,
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)


def classical_vs_pqc_analysis():
    """Compare classical and PQC"""
    st.markdown("### ⚔️ Classical vs Post-Quantum Cryptography")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🔐 Classical (RSA-2048)")
        st.markdown("""
        **Algorithms:**
        - Key Exchange: RSA-2048
        - Signatures: RSA-2048
        - Encryption: AES-256
        
        **Security:**
        - ✓ Secure vs classical computers
        - ✗ Vulnerable to quantum (Shor's algorithm)
        - ⚠️ Est. break year: ~2030
        
        **Performance:**
        - Key gen: ~50ms
        - Encryption: ~1ms
        - Decryption: ~5ms
        
        **Key Sizes:**
        - Public: 294 bytes
        - Private: 1,192 bytes
        """)
    
    with col2:
        st.markdown("#### 🛡️ Post-Quantum (Kyber768)")
        st.markdown("""
        **Algorithms:**
        - Key Exchange: Kyber768
        - Signatures: Dilithium3
        - Encryption: AES-256
        
        **Security:**
        - ✓ Secure vs classical computers
        - ✓ Secure vs quantum computers
        - ✓ Future-proof (50+ years)
        
        **Performance:**
        - Key gen: ~0.5ms (100× faster!)
        - Encryption: ~0.3ms
        - Decryption: ~0.4ms
        
        **Key Sizes:**
        - Public: 1,184 bytes
        - Private: 2,400 bytes
        """)
    
    st.markdown("---")
    
    # Interactive threat calculator
    st.markdown("### 🎯 Threat Calculator")
    
    quantum_year = st.slider("When will quantum computers break RSA?", 2025, 2040, 2030)
    data_lifetime = st.slider("How long must data stay secret?", 1, 50, 10)
    
    current_year = 2024
    data_expiry = current_year + data_lifetime
    
    if data_expiry >= quantum_year:
        st.markdown(f"""
        <div class="danger-box">
            <h3>⚠️ RSA-2048 IS AT RISK!</h3>
            Data must stay secret until: <strong>{data_expiry}</strong><br>
            Quantum threat arrives: <strong>{quantum_year}</strong><br>
            <br>
            <strong>⚠️ Your data will be compromised!</strong><br>
            <strong>Action: Migrate to PQC immediately!</strong>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="success-box">
            <h3>✓ RSA-2048 Currently Safe</h3>
            Data must stay secret until: <strong>{data_expiry}</strong><br>
            Quantum threat arrives: <strong>{quantum_year}</strong><br>
            <br>
            You have {quantum_year - data_expiry} years of margin.
            But start planning PQC migration now!
        </div>
        """, unsafe_allow_html=True)
    
    # Timeline
    fig = go.Figure()
    
    years = list(range(2024, 2051))
    rsa_sec = [100 if y < quantum_year else 0 for y in years]
    pqc_sec = [100] * len(years)
    
    fig.add_trace(go.Scatter(
        x=years, y=rsa_sec,
        fill='tozeroy',
        name='RSA-2048',
        line=dict(color='red', width=2)
    ))
    
    fig.add_trace(go.Scatter(
        x=years, y=pqc_sec,
        fill='tozeroy',
        name='Kyber768 (PQC)',
        line=dict(color='green', width=2)
    ))
    
    fig.add_vline(x=data_expiry, line_dash="dash", 
                  annotation_text=f"Data Expiry ({data_expiry})",
                  line_color="blue")
    fig.add_vline(x=quantum_year, line_dash="dash",
                  annotation_text=f"Quantum Threat ({quantum_year})",
                  line_color="red")
    
    fig.update_layout(
        title='Security Over Time',
        xaxis_title='Year',
        yaxis_title='Security Level (%)',
        yaxis_range=[0, 110],
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)


def defense_layers_analysis():
    """Defense in depth visualization"""
    st.markdown("### 🛡️ Defense in Depth Strategy")
    
    st.write("Security requires multiple layers. Toggle each layer to see protection coverage:")
    
    st.markdown("#### Active Defense Layers:")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        layer1 = st.checkbox("🔐 Encryption (AES-256)", value=True, key="def1")
        layer2 = st.checkbox("✍️ Digital Signatures", value=True, key="def2")
        layer3 = st.checkbox("🔑 Post-Quantum KEM", value=True, key="def3")
    
    with col2:
        layer4 = st.checkbox("📜 PKI/Certificates", value=False, key="def4")
        layer5 = st.checkbox("🔄 Nonce Tracking", value=False, key="def5")
        layer6 = st.checkbox("⏱️ Constant-Time Ops", value=False, key="def6")
    
    with col3:
        layer7 = st.checkbox("🚫 Strict TLS Policy", value=False, key="def7")
        layer8 = st.checkbox("📊 Anomaly Detection", value=False, key="def8")
        layer9 = st.checkbox("🔒 Hardware Security", value=False, key="def9")
    
    active = sum([layer1, layer2, layer3, layer4, layer5, layer6, layer7, layer8, layer9])
    
    # Calculate protection
    protections = {
        'Message Tampering': layer2,
        'Signature Forgery': layer2 and layer3,
        'Brute Force': layer1 and layer3,
        'Ciphertext Attack': layer1,
        'Replay Attack': layer5,
        'MITM': layer4,
        'Downgrade': layer7,
        'Timing Attack': layer6
    }
    
    blocked = sum(protections.values())
    total = len(protections)
    
    st.markdown(f"""
    ### 📊 Protection Summary
    **Active Layers:** {active}/9  
    **Attacks Blocked:** {blocked}/{total} ({(blocked/total*100):.0f}%)
    """)
    
    # Visualization
    fig = go.Figure()
    
    attacks = list(protections.keys())
    protection = [100 if protections[a] else 0 for a in attacks]
    colors = ['green' if p == 100 else 'red' for p in protection]
    labels = ['✓ Blocked' if p == 100 else '✗ Vulnerable' for p in protection]
    
    fig.add_trace(go.Bar(
        y=attacks,
        x=protection,
        orientation='h',
        marker_color=colors,
        text=labels,
        textposition='inside',
        textfont=dict(color='white', size=14)
    ))
    
    fig.update_layout(
        title='Attack Protection Status',
        xaxis_title='Protection (%)',
        yaxis_title='Attack Type',
        xaxis_range=[0, 100],
        showlegend=False,
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Recommendations
    if blocked < total:
        st.warning(f"⚠️ **{total - blocked} vulnerabilities remain!**")
        st.write("**Recommended actions:**")
        
        if not layer4:
            st.write("- Enable PKI/Certificate authentication")
        if not layer5:
            st.write("- Implement nonce/timestamp tracking")
        if not layer6:
            st.write("- Use constant-time crypto implementations")
        if not layer7:
            st.write("- Enforce strict TLS version policy")
        if not layer8:
            st.write("- Add anomaly detection monitoring")
        if not layer9:
            st.write("- Consider Hardware Security Modules (HSM)")
    else:
        st.success("✓ **All attacks blocked!** Complete defense-in-depth achieved.")


# ============= UTILITY FUNCTIONS =============

def update_attack_stats(result):
    """Update attack statistics"""
    st.session_state.attack_stats['total_attacks'] += 1
    
    if result.get('success', False):
        st.session_state.attack_stats['successful_attacks'] += 1
    else:
        st.session_state.attack_stats['failed_attacks'] += 1
    
    st.session_state.attack_stats['attack_history'].append({
        'timestamp': time.time(),
        'attack': result.get('attack_name', 'Unknown'),
        'success': result.get('success', False)
    })


# ============= END OF FILE =============