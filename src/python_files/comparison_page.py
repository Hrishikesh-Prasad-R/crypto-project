"""
PQC vs RSA Comparison Page
Side-by-side comparison of Post-Quantum and Classical cryptography

FILE: comparison_page.py
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import time
import pandas as pd
from python_files.crypto_system import SecureChannel
from python_files.rsa_crypto import RSACrypto


def comparison_page():
    """Main comparison page between PQC and RSA"""
    
    st.markdown("## ⚖️ Post-Quantum vs Classical Cryptography")
    
    st.markdown("""
    <div class="info-box">
        Compare NIST-standardized Post-Quantum algorithms (Kyber768 + Dilithium3) 
        against traditional RSA cryptography across key sizes, performance, and security.
    </div>
    """, unsafe_allow_html=True)
    
    # Comparison tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "📏 Key Size Comparison",
        "⚡ Performance Benchmarks", 
        "🔒 Security Analysis",
        "🧪 Live Demonstration"
    ])
    
    with tab1:
        key_size_comparison()
    
    with tab2:
        performance_comparison()
    
    with tab3:
        security_analysis()
    
    with tab4:
        live_demonstration()


def key_size_comparison():
    """Compare key sizes between PQC and RSA"""
    
    st.markdown("### 📏 Key Size Comparison")
    st.write("How do key sizes compare between Post-Quantum and Classical algorithms?")
    
    # RSA key size selector
    col1, col2 = st.columns([1, 3])
    with col1:
        rsa_size = st.selectbox(
            "RSA Key Size:",
            [2048, 3072, 4096],
            index=0
        )
    
    # Generate keys for comparison
    with st.spinner("Generating keys for comparison..."):
        # PQC keys
        pqc_channel = st.session_state.channel
        pqc_keys = pqc_channel.generate_keys()
        
        # RSA keys
        rsa_crypto = RSACrypto(key_size=rsa_size)
        rsa_pub, rsa_priv, _ = rsa_crypto.generate_keypair()
        rsa_sizes = rsa_crypto.get_key_sizes(rsa_pub, rsa_priv)
    
    # Prepare comparison data
    comparison_data = {
        'Metric': ['Public Key', 'Private Key', 'Ciphertext', 'Signature'],
        'PQC (Kyber+Dilithium)': [
            len(pqc_keys['kem_public']),
            len(pqc_keys['kem_secret']),
            1088,  # Kyber ciphertext
            3309   # Dilithium signature
        ],
        f'RSA-{rsa_size}': [
            rsa_sizes['public_key'],
            rsa_sizes['private_key'],
            rsa_sizes['ciphertext'],
            rsa_sizes['signature']
        ]
    }
    
    df = pd.DataFrame(comparison_data)
    
    # Display table
    st.markdown("#### Size Comparison (bytes)")
    st.dataframe(df, use_container_width=True)
    
    # Bar chart comparison
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        name='PQC (Kyber+Dilithium)',
        x=comparison_data['Metric'],
        y=comparison_data['PQC (Kyber+Dilithium)'],
        marker_color='#1f77b4',
        text=comparison_data['PQC (Kyber+Dilithium)'],
        textposition='auto',
    ))
    
    fig.add_trace(go.Bar(
        name=f'RSA-{rsa_size}',
        x=comparison_data['Metric'],
        y=comparison_data[f'RSA-{rsa_size}'],
        marker_color='#ff7f0e',
        text=comparison_data[f'RSA-{rsa_size}'],
        textposition='auto',
    ))
    
    fig.update_layout(
        title=f"Key & Data Sizes: PQC vs RSA-{rsa_size}",
        xaxis_title="Component",
        yaxis_title="Size (bytes)",
        barmode='group',
        height=500,
        hovermode='x unified'
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Analysis
    st.markdown("#### 📊 Key Observations")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Post-Quantum (Kyber + Dilithium):**
        - Moderate key sizes (~1-4 KB)
        - Compact ciphertext (1088 bytes)
        - Larger signatures (~3.3 KB)
        - Optimized for quantum resistance
        """)
    
    with col2:
        st.markdown(f"""
        **RSA-{rsa_size}:**
        - Compact public keys for smaller sizes
        - Large private keys grow with security level
        - Ciphertext equals key size
        - Smaller signatures than PQC
        """)


def performance_comparison():
    """Benchmark and compare performance"""
    
    st.markdown("### ⚡ Performance Benchmarks")
    st.write("Real-time performance comparison across different operations.")
    
    # Configuration
    col1, col2 = st.columns(2)
    with col1:
        rsa_size = st.selectbox(
            "RSA Key Size:",
            [2048, 3072, 4096],
            index=0,
            key='perf_rsa_size'
        )
    with col2:
        iterations = st.slider(
            "Test Iterations:",
            min_value=10,
            max_value=100,
            value=50,
            step=10
        )
    
    if st.button("🚀 Run Performance Benchmark", type="primary"):
        with st.spinner("Running benchmarks... This may take a moment."):
            results = run_performance_benchmark(rsa_size, iterations)
            display_performance_results(results, rsa_size)


def run_performance_benchmark(rsa_size, iterations):
    """Run comprehensive performance tests"""
    
    pqc_channel = st.session_state.channel
    rsa_crypto = RSACrypto(key_size=rsa_size)
    
    # Test message
    test_message = b"This is a test message for cryptographic benchmarking!"
    
    results = {
        'pqc': {'keygen': [], 'encrypt': [], 'decrypt': [], 'sign': [], 'verify': []},
        'rsa': {'keygen': [], 'encrypt': [], 'decrypt': [], 'sign': [], 'verify': []}
    }
    
    progress_bar = st.progress(0)
    
    for i in range(iterations):
        # PQC benchmarks
        start = time.time()
        pqc_keys = pqc_channel.generate_keys()
        results['pqc']['keygen'].append((time.time() - start) * 1000)
        
        # PQC encryption
        start = time.time()
        package = pqc_channel.send_message(test_message, pqc_keys['kem_public'], pqc_keys['sign_secret'])
        results['pqc']['encrypt'].append((time.time() - start) * 1000)
        
        # PQC decryption
        start = time.time()
        _ = pqc_channel.receive_message(package, pqc_keys['kem_secret'], pqc_keys['sign_public'])
        results['pqc']['decrypt'].append((time.time() - start) * 1000)
        
        # PQC signing
        start = time.time()
        sig = pqc_channel.dilithium.sign(test_message, pqc_keys['sign_secret'])
        results['pqc']['sign'].append((time.time() - start) * 1000)
        
        # PQC verification
        start = time.time()
        _ = pqc_channel.dilithium.verify(sig, test_message, pqc_keys['sign_public'])
        results['pqc']['verify'].append((time.time() - start) * 1000)
        
        # RSA benchmarks
        rsa_pub, rsa_priv, keygen_time = rsa_crypto.generate_keypair()
        results['rsa']['keygen'].append(keygen_time * 1000)
        
        # RSA encryption (use shorter message due to size limits)
        short_msg = test_message[:32]
        ct, enc_time = rsa_crypto.encrypt(short_msg, rsa_pub)
        results['rsa']['encrypt'].append(enc_time * 1000)
        
        # RSA decryption
        _, dec_time = rsa_crypto.decrypt(ct, rsa_priv)
        results['rsa']['decrypt'].append(dec_time * 1000)
        
        # RSA signing
        sig, sign_time = rsa_crypto.sign(test_message, rsa_priv)
        results['rsa']['sign'].append(sign_time * 1000)
        
        # RSA verification
        _, verify_time = rsa_crypto.verify(sig, test_message, rsa_pub)
        results['rsa']['verify'].append(verify_time * 1000)
        
        progress_bar.progress((i + 1) / iterations)
    
    # Calculate averages
    summary = {}
    for system in ['pqc', 'rsa']:
        summary[system] = {
            op: sum(times) / len(times) 
            for op, times in results[system].items()
        }
    
    return summary


def display_performance_results(results, rsa_size):
    """Display performance benchmark results"""
    
    st.success("✓ Benchmark completed!")
    
    # Create comparison DataFrame
    operations = ['keygen', 'encrypt', 'decrypt', 'sign', 'verify']
    operation_names = ['Key Generation', 'Encryption', 'Decryption', 'Signing', 'Verification']
    
    df = pd.DataFrame({
        'Operation': operation_names,
        'PQC (ms)': [results['pqc'][op] for op in operations],
        f'RSA-{rsa_size} (ms)': [results['rsa'][op] for op in operations]
    })
    
    # Add speedup factor
    df['PQC Speedup'] = df[f'RSA-{rsa_size} (ms)'] / df['PQC (ms)']
    
    st.markdown("#### Performance Results (milliseconds)")
    st.dataframe(df.style.format({
        'PQC (ms)': '{:.3f}',
        f'RSA-{rsa_size} (ms)': '{:.3f}',
        'PQC Speedup': '{:.2f}x'
    }), use_container_width=True)
    
    # Bar chart
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        name='PQC',
        x=operation_names,
        y=[results['pqc'][op] for op in operations],
        marker_color='#1f77b4'
    ))
    
    fig.add_trace(go.Bar(
        name=f'RSA-{rsa_size}',
        x=operation_names,
        y=[results['rsa'][op] for op in operations],
        marker_color='#ff7f0e'
    ))
    
    fig.update_layout(
        title=f"Performance Comparison: PQC vs RSA-{rsa_size}",
        xaxis_title="Operation",
        yaxis_title="Time (milliseconds)",
        yaxis_type="log",
        barmode='group',
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Key findings
    st.markdown("#### 🎯 Key Performance Insights")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        keygen_speedup = results['rsa']['keygen'] / results['pqc']['keygen']
        st.metric(
            "Key Generation",
            f"{keygen_speedup:.1f}x faster",
            "PQC advantage",
            delta_color="normal"
        )
    
    with col2:
        encrypt_speedup = results['rsa']['encrypt'] / results['pqc']['encrypt']
        st.metric(
            "Encryption",
            f"{encrypt_speedup:.1f}x faster",
            "PQC advantage",
            delta_color="normal"
        )
    
    with col3:
        sign_speedup = results['rsa']['sign'] / results['pqc']['sign']
        st.metric(
            "Signing",
            f"{sign_speedup:.1f}x faster",
            "PQC advantage",
            delta_color="normal"
        )


def security_analysis():
    """Compare security properties"""
    
    st.markdown("### 🔒 Security Analysis")
    
    st.markdown("""
    <div class="info-box">
        <strong>Critical Difference:</strong> RSA and other classical algorithms are vulnerable 
        to quantum computers running Shor's algorithm, while Post-Quantum algorithms are designed 
        to resist both classical and quantum attacks.
    </div>
    """, unsafe_allow_html=True)
    
    # Security comparison table
    st.markdown("#### Security Properties Comparison")
    
    security_data = {
        'Property': [
            'Classical Computer Security',
            'Quantum Computer Security',
            'NIST Security Level',
            'Key Exchange',
            'Digital Signatures',
            'Mathematical Foundation',
            'Standardization Status'
        ],
        'Post-Quantum (Kyber+Dilithium)': [
            '✅ Secure (192-bit equivalent)',
            '✅ Quantum-Resistant',
            'Level 3 (AES-192)',
            '✅ Kyber768 KEM',
            '✅ Dilithium3',
            'Lattice-based (Module-LWE/LWR)',
            '✅ NIST Standardized (2024)'
        ],
        'RSA-2048': [
            '✅ Secure (112-bit)',
            '❌ Vulnerable to Shor\'s Algorithm',
            'Level 1 (AES-128)',
            '✅ RSA Key Exchange',
            '✅ RSA-PSS',
            'Integer Factorization',
            '✅ Widely Deployed'
        ]
    }
    
    df = pd.DataFrame(security_data)
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    # Quantum threat timeline
    st.markdown("#### ⏰ Quantum Threat Timeline")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **RSA Vulnerability:**
        - **2030-2035**: Large-scale quantum computers expected
        - **Shor's Algorithm**: Breaks RSA in polynomial time
        - **Store-now, decrypt-later**: Current data at risk
        - **Migration urgency**: Must transition before quantum computers arrive
        """)
    
    with col2:
        st.markdown("""
        **Post-Quantum Resilience:**
        - **Quantum-resistant**: No known quantum algorithm breaks PQC
        - **Long-term security**: Designed for 50+ year lifespan
        - **NIST approved**: Rigorous security analysis
        - **Future-proof**: Safe against future quantum advances
        """)
    
    # Visual threat comparison
    fig = go.Figure()
    
    years = list(range(2025, 2046))
    rsa_security = [100] * 5 + [100 - (i * 10) for i in range(20)]  # Degrading after 2030
    pqc_security = [100] * len(years)  # Constant
    
    fig.add_trace(go.Scatter(
        x=years,
        y=rsa_security,
        mode='lines',
        name='RSA-2048 Security',
        line=dict(color='#ff7f0e', width=3),
        fill='tozeroy'
    ))
    
    fig.add_trace(go.Scatter(
        x=years,
        y=pqc_security,
        mode='lines',
        name='PQC Security',
        line=dict(color='#1f77b4', width=3),
        fill='tozeroy'
    ))
    
    fig.add_vline(x=2030, line_dash="dash", line_color="red", 
                  annotation_text="Quantum threat emerges")
    
    fig.update_layout(
        title="Security Level Over Time",
        xaxis_title="Year",
        yaxis_title="Effective Security (%)",
        height=400,
        hovermode='x unified'
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Attack resistance
    st.markdown("#### 🛡️ Attack Resistance")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Classical Attacks:**")
        attacks_classical = {
            'Brute Force': ('✅ Resistant', '✅ Resistant'),
            'Cryptanalysis': ('✅ Resistant', '✅ Resistant'),
            'Side-Channel': ('⚠️ Possible', '⚠️ Possible'),
        }
        for attack, (pqc, rsa) in attacks_classical.items():
            st.write(f"**{attack}:** PQC: {pqc} | RSA: {rsa}")
    
    with col2:
        st.markdown("**Quantum Attacks:**")
        attacks_quantum = {
            'Shor\'s Algorithm': ('✅ Resistant', '❌ Vulnerable'),
            'Grover\'s Algorithm': ('✅ Resistant*', '✅ Resistant*'),
            'Future Quantum': ('✅ Designed for', '❌ Not designed for'),
        }
        for attack, (pqc, rsa) in attacks_quantum.items():
            st.write(f"**{attack}:** PQC: {pqc} | RSA: {rsa}")
        
        st.caption("*Grover provides quadratic speedup; compensated by key sizes")


def live_demonstration():
    """Interactive demonstration of both systems"""
    
    st.markdown("### 🧪 Live Demonstration")
    st.write("Encrypt and sign the same message with both PQC and RSA to compare outputs.")
    
    # Input message
    message = st.text_area(
        "Enter your message:",
        "Hello! This is a secure message encrypted with both PQC and RSA.",
        height=100
    )
    
    # RSA key size
    rsa_size = st.selectbox(
        "RSA Key Size:",
        [2048, 3072, 4096],
        index=0,
        key='demo_rsa_size'
    )
    
    if st.button("🔐 Encrypt & Sign with Both Systems", type="primary"):
        if len(message) > 100:
            st.warning("⚠️ Message truncated to 100 bytes for RSA (due to size limitations)")
            message_bytes = message.encode('utf-8')[:100]
        else:
            message_bytes = message.encode('utf-8')
        
        with st.spinner("Processing with both cryptographic systems..."):
            # Initialize systems
            pqc_channel = st.session_state.channel
            rsa_crypto = RSACrypto(key_size=rsa_size)
            
            # Generate keys
            pqc_keys = pqc_channel.generate_keys()
            rsa_pub, rsa_priv, _ = rsa_crypto.generate_keypair()
            
            # PQC encryption and signing
            pqc_start = time.time()
            pqc_package = pqc_channel.send_message(
                message_bytes, 
                pqc_keys['kem_public'], 
                pqc_keys['sign_secret']
            )
            pqc_time = (time.time() - pqc_start) * 1000
            
            # RSA encryption and signing
            rsa_start = time.time()
            rsa_ct, _ = rsa_crypto.encrypt(message_bytes, rsa_pub)
            rsa_sig, _ = rsa_crypto.sign(message_bytes, rsa_priv)
            rsa_time = (time.time() - rsa_start) * 1000
        
        st.success("✓ Encryption and signing completed!")
        
        # Display results side-by-side
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🔵 Post-Quantum (Kyber + Dilithium)")
            st.metric("Processing Time", f"{pqc_time:.2f} ms")
            
            st.markdown("**Encrypted Output:**")
            st.code(pqc_package['encrypted_message'][:100].hex() + "...", language="text")
            
            st.markdown("**Kyber Ciphertext:**")
            st.code(pqc_package['kyber_ciphertext'][:100].hex() + "...", language="text")
            
            st.markdown("**Dilithium Signature:**")
            st.code(pqc_package['signature'][:100].hex() + "...", language="text")
            
            st.info(f"""
            **Sizes:**
            - Ciphertext: {len(pqc_package['encrypted_message'])} bytes
            - Kyber CT: {len(pqc_package['kyber_ciphertext'])} bytes
            - Signature: {len(pqc_package['signature'])} bytes
            """)
        
        with col2:
            st.markdown(f"#### 🟠 Classical (RSA-{rsa_size})")
            st.metric("Processing Time", f"{rsa_time:.2f} ms")
            
            st.markdown("**Encrypted Output:**")
            st.code(rsa_ct[:100].hex() + "...", language="text")
            
            st.markdown("**RSA Signature:**")
            st.code(rsa_sig[:100].hex() + "...", language="text")
            
            st.info(f"""
            **Sizes:**
            - Ciphertext: {len(rsa_ct)} bytes
            - Signature: {len(rsa_sig)} bytes
            """)
        
        # Comparison summary
        st.markdown("---")
        st.markdown("#### 📊 Comparison Summary")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            speedup = rsa_time / pqc_time if pqc_time > 0 else 0
            st.metric(
                "Speed Comparison",
                f"{speedup:.2f}x",
                "PQC faster" if speedup > 1 else "RSA faster"
            )
        
        with col2:
            total_pqc = len(pqc_package['encrypted_message']) + len(pqc_package['kyber_ciphertext']) + len(pqc_package['signature'])
            total_rsa = len(rsa_ct) + len(rsa_sig)
            st.metric(
                "PQC Total Size",
                f"{total_pqc} bytes",
                f"{total_pqc - total_rsa:+d} vs RSA"
            )
        
        with col3:
            st.metric(
                "RSA Total Size",
                f"{total_rsa} bytes",
                "Classical"
            )
        
        # Verification demonstration
        st.markdown("---")
        st.markdown("#### ✅ Verification Test")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**PQC Decryption & Verification:**")
            try:
                pqc_verify_start = time.time()
                decrypted_pqc = pqc_channel.receive_message(
                    pqc_package,
                    pqc_keys['kem_secret'],
                    pqc_keys['sign_public']
                )
                pqc_verify_time = (time.time() - pqc_verify_start) * 1000
                
                st.success(f"✓ Signature verified ({pqc_verify_time:.2f} ms)")
                st.success(f"✓ Message decrypted: '{decrypted_pqc}'")
            except Exception as e:
                st.error(f"❌ Verification failed: {e}")
        
        with col2:
            st.markdown("**RSA Decryption & Verification:**")
            try:
                rsa_verify_start = time.time()
                decrypted_rsa, _ = rsa_crypto.decrypt(rsa_ct, rsa_priv)
                is_valid, _ = rsa_crypto.verify(rsa_sig, message_bytes, rsa_pub)
                rsa_verify_time = (time.time() - rsa_verify_start) * 1000
                
                if is_valid:
                    st.success(f"✓ Signature verified ({rsa_verify_time:.2f} ms)")
                    st.success(f"✓ Message decrypted: '{decrypted_rsa.decode()}'")
                else:
                    st.error("❌ Signature verification failed")
            except Exception as e:
                st.error(f"❌ Verification failed: {e}")


def create_comparison_summary():
    """Create a visual summary of all comparisons"""
    
    st.markdown("---")
    st.markdown("### 📋 Summary: When to Use Each System")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="success-box">
        <h4>✅ Use Post-Quantum Cryptography When:</h4>
        <ul>
            <li>Long-term data security is critical (10+ years)</li>
            <li>Protection against future quantum computers is needed</li>
            <li>Compliance with modern security standards required</li>
            <li>Building new systems from scratch</li>
            <li>Handling sensitive government/financial data</li>
            <li>Store-now-decrypt-later attacks are a concern</li>
        </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="info-box">
        <h4>⚠️ RSA Still Acceptable For:</h4>
        <ul>
            <li>Legacy system compatibility requirements</li>
            <li>Short-term data (< 5 years)</li>
            <li>Systems being phased out before 2030</li>
            <li>Minimal bandwidth/storage constraints</li>
            <li>Interoperability with older systems</li>
            <li><strong>But plan migration to PQC!</strong></li>
        </ul>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="danger-box">
    <h4>🚨 Important Migration Notice</h4>
    <p>
    <strong>Cryptographically relevant quantum computers are expected by 2030-2035.</strong>
    Organizations should begin migrating to post-quantum cryptography now to ensure:
    </p>
    <ul>
        <li>Data encrypted today remains secure in the quantum era</li>
        <li>Adequate time for testing and deployment</li>
        <li>Compliance with emerging regulations (e.g., NIST standards)</li>
        <li>Protection against "harvest now, decrypt later" attacks</li>
    </ul>
    </div>
    """, unsafe_allow_html=True)