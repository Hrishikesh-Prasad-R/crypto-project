"""
Secure Messaging page for Post-Quantum Cryptography Demo

FILE: secure_messaging.py
"""

import streamlit as st
import time


def secure_messaging_page():
    """Main secure messaging page"""
    st.header("💬 Secure Messaging")
    
    if not st.session_state.alice_keys or not st.session_state.bob_keys:
        st.warning("⚠️ Please generate keys first in the Key Generation page!")
        return
    
    _display_info_box()
    _message_encryption_section()
    
    # Show decrypt section if encrypted package exists
    if 'encrypted_package' in st.session_state and st.session_state.encrypted_package:
        _message_decryption_section()


def _display_info_box():
    """Display information about the encryption scheme"""
    st.markdown("""
    <div class="info-box">
        Messages are encrypted with <strong>AES-256-GCM</strong> using a key established 
        via <strong>Kyber768</strong>, and signed with <strong>Dilithium3</strong>.
    </div>
    """, unsafe_allow_html=True)


def _message_encryption_section():
    """Handle message encryption"""
    col1, col2 = st.columns([2, 1])
    
    with col1:
        message = st.text_area(
            "Message from Alice to Bob:", 
            "Hello Bob! This is a secret message protected by post-quantum cryptography.",
            height=100
        )
    
    with col2:
        st.write("**Message Info:**")
        st.write(f"Length: {len(message)} characters")
        st.write(f"Bytes: {len(message.encode())} bytes")
    
    if st.button("🔐 Encrypt and Send", type="primary"):
        _encrypt_message(message)


def _encrypt_message(message):
    """Encrypt and display encrypted message details"""
    with st.spinner("Encrypting..."):
        start = time.time()
        package = st.session_state.channel.send_message(
            message,
            st.session_state.bob_keys['kem_public'],
            st.session_state.alice_keys['sign_secret']
        )
        encrypt_time = time.time() - start
    
    # Store package in session state
    st.session_state.encrypted_package = package
    st.session_state.encrypt_time = encrypt_time
    st.session_state.original_message = message
    
    st.success(f"✓ Message encrypted in {encrypt_time*1000:.2f}ms")
    
    _display_package_metrics(package)
    _display_encrypted_data(package)


def _display_package_metrics(package):
    """Display metrics for encrypted package"""
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Encrypted Message", f"{len(package['encrypted_message'])} bytes")
    with col2:
        st.metric("Signature", f"{len(package['signature'])} bytes")
    with col3:
        st.metric("Kyber Ciphertext", f"{len(package['kyber_ciphertext'])} bytes")


def _display_encrypted_data(package):
    """Display encrypted data in expandable section"""
    with st.expander("View Encrypted Data"):
        st.write("**Encrypted Message (hex):**")
        st.code(package['encrypted_message'].hex()[:200] + "...")
        st.write("**Signature (hex):**")
        st.code(package['signature'].hex()[:200] + "...")
        st.write("**Kyber Ciphertext (hex):**")
        st.code(package['kyber_ciphertext'].hex()[:100] + "...")


def _message_decryption_section():
    """Handle message decryption and verification"""
    st.markdown("---")
    st.subheader("Bob receives the message...")
    
    package = st.session_state.encrypted_package
    _display_package_metrics(package)
    
    if st.button("🔓 Decrypt and Verify"):
        _decrypt_message(package)


def _decrypt_message(package):
    """Decrypt message and verify signature"""
    with st.spinner("Decrypting and verifying..."):
        start = time.time()
        try:
            decrypted = st.session_state.channel.receive_message(
                package,
                st.session_state.bob_keys['kem_secret'],
                st.session_state.alice_keys['sign_public']
            )
            decrypt_time = time.time() - start
            
            st.success(f"✓ Message decrypted and verified in {decrypt_time*1000:.2f}ms")
            
            _display_decryption_success(decrypted)
            _display_timing_comparison(decrypt_time)
            
        except ValueError as e:
            st.error(f"❌ Verification failed: {e}")
            _display_decryption_failure()


def _display_decryption_success(decrypted):
    """Display successful decryption result"""
    st.markdown(f"""
    <div class="success-box">
        <strong>✓ Signature Verified - Message is authentic!</strong><br>
        <strong>✓ Decrypted Message:</strong><br>
        "{decrypted}"
    </div>
    """, unsafe_allow_html=True)


def _display_timing_comparison(decrypt_time):
    """Display timing comparison if encryption time is available"""
    if hasattr(st.session_state, 'encrypt_time'):
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Encryption Time", f"{st.session_state.encrypt_time*1000:.2f}ms")
        with col2:
            st.metric("Decryption Time", f"{decrypt_time*1000:.2f}ms")


def _display_decryption_failure():
    """Display information about decryption failure"""
    st.markdown("""
    <div class="danger-box">
        <strong>❌ Message Integrity Compromised!</strong><br>
        <br>
        Possible reasons:<br>
        • Message was tampered with during transmission<br>
        • Signature was forged or modified<br>
        • Wrong keys were used for verification<br>
        <br>
        🛡️ The cryptographic system protected you from accepting invalid data!
    </div>
    """, unsafe_allow_html=True)


def display_encryption_flow():
    """Display visual encryption flow diagram"""
    st.markdown("### 🔄 Encryption Flow")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.markdown("**1️⃣ Message**<br>Plain text", unsafe_allow_html=True)
    with col2:
        st.markdown("**2️⃣ Sign**<br>Dilithium3", unsafe_allow_html=True)
    with col3:
        st.markdown("**3️⃣ Encrypt**<br>AES-256-GCM", unsafe_allow_html=True)
    with col4:
        st.markdown("**4️⃣ Wrap Key**<br>Kyber768", unsafe_allow_html=True)
    with col5:
        st.markdown("**5️⃣ Send**<br>Secure package", unsafe_allow_html=True)