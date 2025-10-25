"""
Interactive Web Interface using Streamlit
Beautiful UI for demonstrating post-quantum cryptography
"""

import streamlit as st
from crypto_system import SecureChannel
import time
import plotly.graph_objects as go
import plotly.express as px
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Page config
st.set_page_config(
    page_title="Post-Quantum Crypto Demo",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
    }
    .danger-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
    }
    .info-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d1ecf1;
        border: 1px solid #bee5eb;
        color: #0c5460;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'channel' not in st.session_state:
    st.session_state.channel = SecureChannel()
if 'alice_keys' not in st.session_state:
    st.session_state.alice_keys = None
if 'bob_keys' not in st.session_state:
    st.session_state.bob_keys = None

def main():
    # Header
    st.markdown('<h1 class="main-header">🔒 Post-Quantum Cryptography Demo</h1>', 
                unsafe_allow_html=True)
    
    st.markdown("""
    <div class="info-box">
        <strong>🛡️ Secure Against Quantum Computers</strong><br>
        This demonstration uses NIST-standardized post-quantum algorithms:
        <strong>Kyber768</strong> (key exchange) and <strong>Dilithium3</strong> (signatures)
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    st.sidebar.title("🎯 Navigation")
    page = st.sidebar.radio(
        "Choose a demonstration:",
        ["🔑 Key Generation", "💬 Secure Messaging", "⚔️ Attack Simulations", 
         "📊 Performance Analysis", "🧮 Quantum Calculator"]
    )
    
    if page == "🔑 Key Generation":
        key_generation_page()
    elif page == "💬 Secure Messaging":
        secure_messaging_page()
    elif page == "⚔️ Attack Simulations":
        attack_simulations_page()
    elif page == "📊 Performance Analysis":
        performance_analysis_page()
    elif page == "🧮 Quantum Calculator":
        quantum_calculator_page()

def key_generation_page():
    st.header("🔑 Key Generation")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("👩 Alice")
        if st.button("Generate Alice's Keys", key="alice_gen"):
            with st.spinner("Generating keys..."):
                start = time.time()
                st.session_state.alice_keys = st.session_state.channel.generate_keys()
                elapsed = time.time() - start
            
            st.success(f"✓ Keys generated in {elapsed*1000:.2f}ms")
            
            st.write("**Key Sizes:**")
            st.write(f"- Kyber768 Public: {len(st.session_state.alice_keys['kem_public'])} bytes")
            st.write(f"- Kyber768 Secret: {len(st.session_state.alice_keys['kem_secret'])} bytes")
            st.write(f"- Dilithium3 Public: {len(st.session_state.alice_keys['sign_public'])} bytes")
            st.write(f"- Dilithium3 Secret: {len(st.session_state.alice_keys['sign_secret'])} bytes")
            
            with st.expander("View Public Keys (Hex)"):
                st.code(st.session_state.alice_keys['kem_public'].hex()[:200] + "...")
        
        if st.session_state.alice_keys:
            st.markdown('<div class="success-box">✓ Alice\'s keys are ready</div>', 
                       unsafe_allow_html=True)
    
    with col2:
        st.subheader("👨 Bob")
        if st.button("Generate Bob's Keys", key="bob_gen"):
            with st.spinner("Generating keys..."):
                start = time.time()
                st.session_state.bob_keys = st.session_state.channel.generate_keys()
                elapsed = time.time() - start
            
            st.success(f"✓ Keys generated in {elapsed*1000:.2f}ms")
            
            st.write("**Key Sizes:**")
            st.write(f"- Kyber768 Public: {len(st.session_state.bob_keys['kem_public'])} bytes")
            st.write(f"- Kyber768 Secret: {len(st.session_state.bob_keys['kem_secret'])} bytes")
            st.write(f"- Dilithium3 Public: {len(st.session_state.bob_keys['sign_public'])} bytes")
            st.write(f"- Dilithium3 Secret: {len(st.session_state.bob_keys['sign_secret'])} bytes")
            
            with st.expander("View Public Keys (Hex)"):
                st.code(st.session_state.bob_keys['kem_public'].hex()[:200] + "...")
        
        if st.session_state.bob_keys:
            st.markdown('<div class="success-box">✓ Bob\'s keys are ready</div>', 
                       unsafe_allow_html=True)
    
    # Visualization
    if st.session_state.alice_keys and st.session_state.bob_keys:
        st.markdown("---")
        st.subheader("📊 Key Size Visualization")
        
        data = {
            'Key Type': ['Kyber Public', 'Kyber Secret', 'Dilithium Public', 'Dilithium Secret'],
            'Size (bytes)': [1184, 2400, 1952, 4032]
        }
        
        fig = px.bar(data, x='Key Type', y='Size (bytes)', 
                    title='Post-Quantum Key Sizes',
                    color='Size (bytes)',
                    color_continuous_scale='blues')
        st.plotly_chart(fig, use_container_width=True)

def secure_messaging_page():
    st.header("💬 Secure Messaging")
    
    if not st.session_state.alice_keys or not st.session_state.bob_keys:
        st.warning("⚠️ Please generate keys first in the Key Generation page!")
        return
    
    st.markdown("""
    <div class="info-box">
        Messages are encrypted with <strong>AES-256-GCM</strong> using a key established 
        via <strong>Kyber768</strong>, and signed with <strong>Dilithium3</strong>.
    </div>
    """, unsafe_allow_html=True)
    
    # Message input
    col1, col2 = st.columns([2, 1])
    
    with col1:
        message = st.text_area("Message from Alice to Bob:", 
                              "Hello Bob! This is a secret message protected by post-quantum cryptography.",
                              height=100)
    
    with col2:
        st.write("**Message Info:**")
        st.write(f"Length: {len(message)} characters")
        st.write(f"Bytes: {len(message.encode())} bytes")
    
    if st.button("🔐 Encrypt and Send", type="primary"):
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
        
        st.success(f"✓ Message encrypted in {encrypt_time*1000:.2f}ms")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Encrypted Message", f"{len(package['encrypted_message'])} bytes")
        with col2:
            st.metric("Signature", f"{len(package['signature'])} bytes")
        with col3:
            st.metric("Kyber Ciphertext", f"{len(package['kyber_ciphertext'])} bytes")
        
        with st.expander("View Encrypted Data"):
            st.write("**Encrypted Message (hex):**")
            st.code(package['encrypted_message'].hex()[:200] + "...")
            st.write("**Signature (hex):**")
            st.code(package['signature'].hex()[:200] + "...")
    
    # Show decrypt button if package exists
    if 'encrypted_package' in st.session_state and st.session_state.encrypted_package:
        st.markdown("---")
        st.subheader("Bob receives the message...")
        
        # Display encrypted data info
        package = st.session_state.encrypted_package
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Encrypted Message", f"{len(package['encrypted_message'])} bytes")
        with col2:
            st.metric("Signature", f"{len(package['signature'])} bytes")
        with col3:
            st.metric("Kyber Ciphertext", f"{len(package['kyber_ciphertext'])} bytes")
        
        if st.button("🔓 Decrypt and Verify"):
            with st.spinner("Decrypting and verifying..."):
                start = time.time()
                try:
                    decrypted = st.session_state.channel.receive_message(
                        st.session_state.encrypted_package,
                        st.session_state.bob_keys['kem_secret'],
                        st.session_state.alice_keys['sign_public']
                    )
                    decrypt_time = time.time() - start
                    
                    st.success(f"✓ Message decrypted and verified in {decrypt_time*1000:.2f}ms")
                    
                    st.markdown(f"""
                    <div class="success-box">
                        <strong>✓ Signature Verified - Message is authentic!</strong><br>
                        <strong>✓ Decrypted Message:</strong><br>
                        "{decrypted}"
                    </div>
                    """, unsafe_allow_html=True)
                    
                except ValueError as e:
                    st.error(f"❌ Verification failed: {e}")

def attack_simulations_page():
    st.header("⚔️ Attack Simulations")
    
    attack_type = st.selectbox(
        "Choose an attack to simulate:",
        ["Man-in-the-Middle", "Message Tampering", "Signature Forgery"]
    )

def performance_analysis_page():
    st.header("📊 Performance Analysis")
    
    st.subheader("⚡ Real-Time Benchmarking")
    
    iterations = st.slider("Number of iterations:", 5, 5000, 10)
    
    if st.button("Run Benchmark", type="primary"):
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        pqc_times = {'keygen': [], 'encrypt': [], 'decrypt': []}
        
        for i in range(iterations):
            status_text.text(f"Running iteration {i+1}/{iterations}...")
            
            # Keygen
            start = time.time()
            keys = st.session_state.channel.generate_keys()
            pqc_times['keygen'].append((time.time() - start) * 1000)
            
            # Encrypt
            start = time.time()
            package = st.session_state.channel.send_message(
                "Test message",
                keys['kem_public'],
                keys['sign_secret']
            )
            pqc_times['encrypt'].append((time.time() - start) * 1000)
            
            # Decrypt
            start = time.time()
            decrypted = st.session_state.channel.receive_message(
                package,
                keys['kem_secret'],
                keys['sign_public']
            )
            pqc_times['decrypt'].append((time.time() - start) * 1000)
            
            progress_bar.progress((i + 1) / iterations)
        
        status_text.text("Benchmark complete!")
        
        # Display results
        col1, col2, col3 = st.columns(3)
        
        import numpy as np
        
        with col1:
            avg = np.mean(pqc_times['keygen'])
            std = np.std(pqc_times['keygen'])
            st.metric("Key Generation", f"{avg:.2f}ms", f"±{std:.2f}ms")
        
        with col2:
            avg = np.mean(pqc_times['encrypt'])
            std = np.std(pqc_times['encrypt'])
            st.metric("Encryption", f"{avg:.2f}ms", f"±{std:.2f}ms")
        
        with col3:
            avg = np.mean(pqc_times['decrypt'])
            std = np.std(pqc_times['decrypt'])
            st.metric("Decryption", f"{avg:.2f}ms", f"±{std:.2f}ms")
        
        # Plot
        fig = go.Figure()
        fig.add_trace(go.Box(y=pqc_times['keygen'], name='Key Gen'))
        fig.add_trace(go.Box(y=pqc_times['encrypt'], name='Encrypt'))
        fig.add_trace(go.Box(y=pqc_times['decrypt'], name='Decrypt'))
        
        fig.update_layout(
            title='Performance Distribution',
            yaxis_title='Time (milliseconds)',
            showlegend=True
        )
        
        st.plotly_chart(fig, use_container_width=True)

def quantum_calculator_page():
    st.header("🧮 Quantum Threat Calculator")
    
    st.markdown("""
    <div class="info-box">
        Calculate when various cryptographic algorithms will be vulnerable to quantum computers
    </div>
    """, unsafe_allow_html=True)
    
    algorithm = st.selectbox(
        "Select Algorithm:",
        ["RSA-2048", "RSA-3072", "RSA-4096", "ECC-256", "Kyber768", "Dilithium3"]
    )
    
    data_lifetime = st.slider("How long must the data remain secret? (years)", 1, 50, 10)
    
    if st.button("Calculate Threat Level"):
        current_year = 2024
        target_year = current_year + data_lifetime
        
        # Threat estimates
        quantum_break_years = {
            "RSA-2048": 2030,
            "RSA-3072": 2033,
            "RSA-4096": 2035,
            "ECC-256": 2028,
            "Kyber768": None,  # Not breakable
            "Dilithium3": None
        }
        
        break_year = quantum_break_years[algorithm]
        
        if break_year is None:
            st.markdown(f"""
            <div class="success-box">
                <h3>✓ SECURE</h3>
                <strong>{algorithm}</strong> is quantum-resistant!<br>
                Your data will remain secure for {data_lifetime} years and beyond.
            </div>
            """, unsafe_allow_html=True)
        elif target_year >= break_year:
            years_until = break_year - current_year
            st.markdown(f"""
            <div class="danger-box">
                <h3>⚠️ AT RISK</h3>
                <strong>{algorithm}</strong> will likely be broken by {break_year}<br>
                Your data needs protection until {target_year}<br>
                <strong>RECOMMENDATION: Migrate to post-quantum cryptography NOW!</strong>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="info-box">
                <h3>✓ Currently Secure</h3>
                <strong>{algorithm}</strong> should be secure until ~{break_year}<br>
                Your data needs protection until {target_year}<br>
                You have time, but consider planning migration to PQC.
            </div>
            """, unsafe_allow_html=True)
        
        # Timeline visualization
        years = list(range(2024, 2045))
        risk_levels = []
        
        for year in years:
            if break_year and year >= break_year:
                risk_levels.append(100)
            elif break_year:
                risk_levels.append(min(100, (year - 2024) * 10))
            else:
                risk_levels.append(0)
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=years,
            y=risk_levels,
            fill='tozeroy',
            name='Risk Level',
            line=dict(color='red' if break_year else 'green')
        ))
        
        fig.update_layout(
            title=f'Quantum Threat Timeline for {algorithm}',
            xaxis_title='Year',
            yaxis_title='Risk Level (%)',
            yaxis_range=[0, 100]
        )
        
        if data_lifetime:
            fig.add_vline(x=target_year, line_dash="dash", 
                         annotation_text="Data Lifetime End")
        
        st.plotly_chart(fig, use_container_width=True)

if __name__ == "__main__":
    main()