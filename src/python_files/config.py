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
        'ciphertext_size': 1088,
        'quantum_secure': True
    },
    'dilithium3': {
        'name': 'Dilithium3',
        'type': 'Digital Signature',
        'security_level': 'NIST Level 3',
        'public_key_size': 1952,
        'secret_key_size': 4032,
        'signature_size': 3309,
        'quantum_secure': True
    },
    'rsa2048': {
        'name': 'RSA-2048',
        'type': 'Asymmetric Encryption & Signature',
        'security_level': 'NIST Level 1 (AES-128 equivalent)',
        'public_key_size': 294,  # Typical PEM size
        'secret_key_size': 1675,  # Typical PEM size
        'signature_size': 256,
        'quantum_secure': False
    },
    'rsa3072': {
        'name': 'RSA-3072',
        'type': 'Asymmetric Encryption & Signature',
        'security_level': 'NIST Level 2 (AES-128 equivalent)',
        'public_key_size': 422,
        'secret_key_size': 2455,
        'signature_size': 384,
        'quantum_secure': False
    },
    'rsa4096': {
        'name': 'RSA-4096',
        'type': 'Asymmetric Encryption & Signature',
        'security_level': 'NIST Level 3 (AES-192 equivalent)',
        'public_key_size': 550,
        'secret_key_size': 3243,
        'signature_size': 512,
        'quantum_secure': False
    }
}

# Quantum Threat Estimates
QUANTUM_BREAK_YEARS = {
    "RSA-2048": 2030,
    "RSA-3072": 2033,
    "RSA-4096": 2035,
    "ECC-256": 2028,
    "Kyber768": None,  # Not breakable by known quantum algorithms
    "Dilithium3": None
}

# Performance Data (example baseline values in milliseconds)
PERFORMANCE_BASELINES = {
    'pqc': {
        'keygen': 0.5,
        'encrypt': 0.3,
        'decrypt': 0.4,
        'sign': 0.8,
        'verify': 0.3
    },
    'rsa2048': {
        'keygen': 50.0,
        'encrypt': 1.0,
        'decrypt': 5.0,
        'sign': 4.0,
        'verify': 0.5
    },
    'rsa3072': {
        'keygen': 150.0,
        'encrypt': 1.5,
        'decrypt': 12.0,
        'sign': 10.0,
        'verify': 0.8
    },
    'rsa4096': {
        'keygen': 350.0,
        'encrypt': 2.0,
        'decrypt': 25.0,
        'sign': 20.0,
        'verify': 1.0
    }
}

# Comparison metrics
COMPARISON_CATEGORIES = {
    'Performance': ['Key Generation Speed', 'Encryption Speed', 'Decryption Speed', 'Signing Speed', 'Verification Speed'],
    'Size': ['Public Key Size', 'Private Key Size', 'Ciphertext Size', 'Signature Size'],
    'Security': ['Classical Security', 'Quantum Security', 'Future-Proof', 'Standardization'],
    'Practical': ['Deployment Maturity', 'Hardware Support', 'Bandwidth Efficiency', 'Battery Impact']
}