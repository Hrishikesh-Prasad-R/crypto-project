"""
Configuration and styling for Post-Quantum Cryptography Demo
Centralized settings and CSS styles

FILE: config.py
"""

import streamlit as st

# Page Configuration
def setup_page_config():
    """Configure Streamlit page settings"""
    st.set_page_config(
        page_title="Post-Quantum Crypto Demo",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )

# Custom CSS Styles
CUSTOM_CSS = """
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
"""

def apply_custom_styles():
    """Apply custom CSS to the application"""
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Algorithm Information
ALGORITHM_INFO = {
    'kyber768': {
        'name': 'Kyber768',
        'type': 'Key Encapsulation Mechanism (KEM)',
        'security_level': 'NIST Level 3 (AES-192 equivalent)',
        'public_key_size': 1184,
        'secret_key_size': 2400,
        'ciphertext_size': 1088
    },
    'dilithium3': {
        'name': 'Dilithium3',
        'type': 'Digital Signature',
        'security_level': 'NIST Level 3',
        'public_key_size': 1952,
        'secret_key_size': 4032,
        'signature_size': 3309
    }
}

# Quantum Threat Estimates
QUANTUM_BREAK_YEARS = {
    "RSA-2048": 2030,
    "RSA-3072": 2033,
    "RSA-4096": 2035,
    "ECC-256": 2028,
    "Kyber768": None,  # Not breakable
    "Dilithium3": None
}

# Performance Data (example baseline values)
PERFORMANCE_BASELINES = {
    'pqc': {
        'keygen': 0.5,  # milliseconds
        'encrypt': 0.3,
        'decrypt': 0.4
    },
    'rsa': {
        'keygen': 50.0,
        'encrypt': 1.0,
        'decrypt': 5.0
    }
}