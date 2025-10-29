"""
Main entry point for Post-Quantum Cryptography Demo
Run with: streamlit run streamlit_app.py

FILE: streamlit_app.py
"""

import streamlit as st
from python_files.config import setup_page_config, apply_custom_styles
from python_files.diagnostics import check_crypto_initialization, display_initialization_error, initialize_session_state
from python_files.key_generation import key_generation_page
from python_files.secure_messaging import secure_messaging_page
from attack_simulations.attacks import attack_simulations_page
from python_files.performance_analysis import performance_analysis_page
from python_files.comparison_page import comparison_page

# Must be first Streamlit command
setup_page_config()

# Check if crypto system can be initialized
CRYPTO_INITIALIZED, CRYPTO_ERROR, CRYPTO_TRACEBACK = check_crypto_initialization()

# Apply custom styles
apply_custom_styles()

# Display error and stop if crypto failed
if not CRYPTO_INITIALIZED:
    display_initialization_error(CRYPTO_ERROR, CRYPTO_TRACEBACK)
    st.stop()

# Initialize session state
initialize_session_state()

# Main application
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
    
    # Sidebar navigation
    st.sidebar.title("🎯 Navigation")
    page = st.sidebar.radio(
        "Choose a demonstration:",
        ["🔑 Key Generation", 
         "💬 Secure Messaging", 
         "⚔️ Attack Simulations", 
         "📊 Performance Analysis", 
         "⚖️ PQC vs RSA Comparison"]
    )
    
    # Route to appropriate page
    if page == "🔑 Key Generation":
        key_generation_page()
    elif page == "💬 Secure Messaging":
        secure_messaging_page()
    elif page == "⚔️ Attack Simulations":
        attack_simulations_page()
    elif page == "📊 Performance Analysis":
        performance_analysis_page()
    elif page == "⚖️ PQC vs RSA Comparison":
        comparison_page()

if __name__ == "__main__":
    main()