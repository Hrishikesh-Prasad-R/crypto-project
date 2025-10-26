"""
Diagnostics and error handling for crypto system initialization

FILE: diagnostics.py
"""

import streamlit as st
import sys
from pathlib import Path


def display_initialization_error(error, traceback_str):
    """Display comprehensive error diagnostics"""
    st.error("### ❌ Failed to Initialize Cryptographic System")
    st.error(f"**Error Type:** {type(error).__name__}")
    st.error(f"**Error Message:** {str(error)}")
    
    with st.expander("🔍 Full Error Traceback (click to expand)", expanded=True):
        st.code(traceback_str)
    
    st.write("---")
    st.write("### 🔍 Diagnostic Information")
    
    _display_system_info()
    _display_file_system_info()
    _display_possible_solutions()


def _display_system_info():
    """Display system information in columns"""
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**System Information:**")
        st.write(f"- Python version: {sys.version}")
        st.write(f"- Platform: {sys.platform}")
        st.write(f"- Current directory: {Path.cwd()}")
    
    with col2:
        _check_library_files()


def _check_library_files():
    """Check for presence of required shared libraries"""
    src_dir = Path(__file__).parent
    st.write("**File System:**")
    st.write(f"- Script directory: {src_dir}")
    
    # Check for .so files (Linux)
    kyber_so = src_dir / "libpqcrystals_kyber768_ref.so"
    dilithium_so = src_dir / "libpqcrystals_dilithium3_ref.so"
    
    # Check for .dll files (Windows)
    kyber_dll = src_dir / "libpqcrystals_kyber768_ref.dll"
    dilithium_dll = src_dir / "libpqcrystals_dilithium3_ref.dll"
    
    st.write(f"- Kyber .so exists: {kyber_so.exists()}")
    st.write(f"- Dilithium .so exists: {dilithium_so.exists()}")
    st.write(f"- Kyber .dll exists: {kyber_dll.exists()}")
    st.write(f"- Dilithium .dll exists: {dilithium_dll.exists()}")


def _display_file_system_info():
    """Display all files in the current directory"""
    src_dir = Path(__file__).parent
    
    with st.expander("📁 All Files in Directory"):
        files = list(src_dir.glob('*'))
        for f in sorted(files):
            st.write(f"- {f.name} ({f.stat().st_size} bytes)")


def _display_possible_solutions():
    """Display troubleshooting suggestions"""
    st.write("---")
    st.write("### 💡 Possible Solutions")
    st.info("""
    **If you're seeing this error, here's what might be wrong:**
    
    1. **Missing system dependencies** - The .so files need `libgomp1` installed
       - Make sure `packages.txt` exists with `libgomp1` in it
    
    2. **.so files not in repository** - The shared libraries need to be committed to Git
       - Run: `git add src/*.so && git commit -m "Add shared libraries" && git push`
    
    3. **Incompatible .so files** - The libraries might be compiled for a different Linux version
       - Try recompiling on Ubuntu 22.04 or use the liboqs-python fallback
    
    4. **File permission issues** - The .so files might not be executable
       - This is less likely on Streamlit Cloud but possible
    
    5. **Missing Python dependencies** - Check if all required packages are installed
       - Verify: pycryptodome, numpy, plotly are installed
    """)


def check_crypto_initialization():
    """
    Attempt to initialize crypto system and return status
    
    Returns:
        tuple: (success: bool, error: Exception or None, traceback: str or None)
    """
    try:
        from python_files.crypto_system import SecureChannel
        import time
        import plotly.graph_objects as go
        import plotly.express as px
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        
        return True, None, None
        
    except Exception as e:
        import traceback
        return False, e, traceback.format_exc()


def initialize_session_state():
    """Initialize all session state variables"""
    if 'channel' not in st.session_state:
        try:
            from python_files.crypto_system import SecureChannel
            with st.spinner("Initializing cryptographic system..."):
                st.session_state.channel = SecureChannel()
            st.success("✓ Cryptographic system initialized successfully!")
        except Exception as e:
            st.error("### ❌ Failed to Create SecureChannel Instance")
            st.error(f"**Error Type:** {type(e).__name__}")
            st.error(f"**Error Message:** {str(e)}")
            
            import traceback
            with st.expander("🔍 Full Error Traceback"):
                st.code(traceback.format_exc())
            
            st.stop()
    
    # Initialize key storage
    if 'alice_keys' not in st.session_state:
        st.session_state.alice_keys = None
    if 'bob_keys' not in st.session_state:
        st.session_state.bob_keys = None
    
    # Initialize attack statistics
    if 'attack_stats' not in st.session_state:
        st.session_state.attack_stats = {
            'total_attacks': 0,
            'successful_attacks': 0,
            'failed_attacks': 0,
            'attack_history': []
        }