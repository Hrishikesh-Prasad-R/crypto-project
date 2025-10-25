"""
Key Generation page for Post-Quantum Cryptography Demo

FILE: key_generation.py
"""

import streamlit as st
import time
import plotly.express as px
from config import ALGORITHM_INFO


def key_generation_page():
    """Main key generation page"""
    st.header("🔑 Key Generation")
    
    col1, col2 = st.columns(2)
    
    with col1:
        _alice_key_section()
    
    with col2:
        _bob_key_section()
    
    # Visualization if both keys exist
    if st.session_state.alice_keys and st.session_state.bob_keys:
        _display_key_visualization()


def _alice_key_section():
    """Alice's key generation section"""
    st.subheader("👩 Alice")
    
    if st.button("Generate Alice's Keys", key="alice_gen"):
        with st.spinner("Generating keys..."):
            start = time.time()
            st.session_state.alice_keys = st.session_state.channel.generate_keys()
            elapsed = time.time() - start
        
        st.success(f"✓ Keys generated in {elapsed*1000:.2f}ms")
        
        _display_key_info(st.session_state.alice_keys)
    
    if st.session_state.alice_keys:
        st.markdown('<div class="success-box">✓ Alice\'s keys are ready</div>', 
                   unsafe_allow_html=True)


def _bob_key_section():
    """Bob's key generation section"""
    st.subheader("👨 Bob")
    
    if st.button("Generate Bob's Keys", key="bob_gen"):
        with st.spinner("Generating keys..."):
            start = time.time()
            st.session_state.bob_keys = st.session_state.channel.generate_keys()
            elapsed = time.time() - start
        
        st.success(f"✓ Keys generated in {elapsed*1000:.2f}ms")
        
        _display_key_info(st.session_state.bob_keys)
    
    if st.session_state.bob_keys:
        st.markdown('<div class="success-box">✓ Bob\'s keys are ready</div>', 
                   unsafe_allow_html=True)


def _display_key_info(keys):
    """Display information about generated keys"""
    st.write("**Key Sizes:**")
    st.write(f"- Kyber768 Public: {len(keys['kem_public'])} bytes")
    st.write(f"- Kyber768 Secret: {len(keys['kem_secret'])} bytes")
    st.write(f"- Dilithium3 Public: {len(keys['sign_public'])} bytes")
    st.write(f"- Dilithium3 Secret: {len(keys['sign_secret'])} bytes")
    
    with st.expander("View Public Keys (Hex)"):
        st.code(keys['kem_public'].hex()[:200] + "...")


def _display_key_visualization():
    """Display key size comparison chart"""
    st.markdown("---")
    st.subheader("📊 Key Size Visualization")
    
    data = {
        'Key Type': [
            'Kyber Public', 
            'Kyber Secret', 
            'Dilithium Public', 
            'Dilithium Secret'
        ],
        'Size (bytes)': [
            ALGORITHM_INFO['kyber768']['public_key_size'],
            ALGORITHM_INFO['kyber768']['secret_key_size'],
            ALGORITHM_INFO['dilithium3']['public_key_size'],
            ALGORITHM_INFO['dilithium3']['secret_key_size']
        ]
    }
    
    fig = px.bar(
        data, 
        x='Key Type', 
        y='Size (bytes)', 
        title='Post-Quantum Key Sizes',
        color='Size (bytes)',
        color_continuous_scale='blues'
    )
    
    st.plotly_chart(fig, use_container_width=True)


def display_algorithm_comparison():
    """Display comparison between classical and PQC algorithms"""
    st.markdown("### 📊 Algorithm Comparison")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Classical (RSA-2048)")
        st.write("- Public Key: 294 bytes")
        st.write("- Private Key: 1,192 bytes")
        st.write("- Security: ✗ Quantum vulnerable")
        st.write("- Speed: Slow keygen (~50ms)")
    
    with col2:
        st.markdown("#### Post-Quantum (Kyber768)")
        st.write("- Public Key: 1,184 bytes")
        st.write("- Private Key: 2,400 bytes")
        st.write("- Security: ✓ Quantum resistant")
        st.write("- Speed: Fast keygen (~0.5ms)")