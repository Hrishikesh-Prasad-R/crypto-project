"""
Performance Analysis page for Post-Quantum Cryptography Demo

FILE: performance_analysis.py
"""

import streamlit as st
import time
import numpy as np
import plotly.graph_objects as go


def performance_analysis_page():
    """Main performance analysis page"""
    st.header("📊 Performance Analysis")
    
    st.subheader("⚡ Real-Time Benchmarking")
    
    iterations = st.slider("Number of iterations:", 5, 100, 10)
    
    if st.button("Run Benchmark", type="primary"):
        _run_benchmark(iterations)


def _run_benchmark(iterations):
    """Execute benchmark tests"""
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
    _display_benchmark_results(pqc_times)
    _display_performance_charts(pqc_times)


def _display_benchmark_results(pqc_times):
    """Display statistical summary of benchmark results"""
    col1, col2, col3 = st.columns(3)
    
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


def _display_performance_charts(pqc_times):
    """Display performance visualization charts"""
    # Box plot
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