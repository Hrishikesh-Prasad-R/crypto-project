"""
Post-Quantum Cryptography Attack Simulation Suite
Main entry point with proper error handling
"""

import streamlit as st
from .attack_cryptographic import CryptographicAttacks
from .attack_protocol import ProtocolAttacks
from .attack_analysis import AttackAnalysis
from .attack_logger import AttackLogger


def attack_simulations_page():
    """Main attack simulations page with error handling"""
    
    # Apply CSS FIRST - makes it available to all components
    add_custom_css()
    
    st.header("⚔️ Cryptographic Attack Simulation Suite")
    
    # Initialize attack logger
    if 'attack_logger' not in st.session_state:
        st.session_state.attack_logger = AttackLogger()
    
    # Validate prerequisites
    if not validate_prerequisites():
        return
    
    # Display dashboard
    try:
        display_attack_dashboard()
    except Exception as e:
        st.warning(f"Dashboard error: {e}")
    
    st.markdown("---")
    
    # Main navigation
    attack_category = st.radio(
        "**Select Attack Category:**",
        ["🛡️ Cryptographic Attacks (Algorithm-Level)", 
         "⚠️ Protocol Attacks (System-Level)",
         "📊 Comprehensive Analysis & Comparison"],
        horizontal=False
    )
    
    st.markdown("---")
    
    # Route to appropriate section with error handling
    try:
        if attack_category == "🛡️ Cryptographic Attacks (Algorithm-Level)":
            crypto_attacks = CryptographicAttacks(
                st.session_state.channel,
                st.session_state.alice_keys,
                st.session_state.bob_keys,
                st.session_state.attack_logger
            )
            crypto_attacks.render()
            
        elif attack_category == "⚠️ Protocol Attacks (System-Level)":
            protocol_attacks = ProtocolAttacks(
                st.session_state.channel,
                st.session_state.alice_keys,
                st.session_state.bob_keys,
                st.session_state.attack_logger
            )
            protocol_attacks.render()
            
        else:
            analysis = AttackAnalysis(st.session_state.attack_logger)
            analysis.render()
            
    except Exception as e:
        st.error(f"❌ Error executing attack: {e}")
        with st.expander("🔍 Error Details (for debugging)"):
            st.exception(e)


def validate_prerequisites():
    """Validate all prerequisites are met"""
    
    if 'alice_keys' not in st.session_state or 'bob_keys' not in st.session_state:
        st.warning("⚠️ Please generate keys first in the Key Generation page!")
        return False
    
    if not st.session_state.alice_keys or not st.session_state.bob_keys:
        st.warning("⚠️ Keys are empty. Please regenerate in Key Generation page!")
        return False
    
    if 'channel' not in st.session_state:
        st.error("❌ Communication channel not initialized!")
        st.info("Please visit the Key Generation page first to initialize the system.")
        return False
    
    return True


def display_attack_dashboard():
    """Professional statistics dashboard"""
    
    logger = st.session_state.attack_logger
    stats = logger.get_statistics()
    
    st.markdown("### 📊 Attack Simulation Statistics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Simulations", stats.get('total_attacks', 0))
    
    with col2:
        total = max(stats.get('total_attacks', 1), 1)
        success_rate = (stats.get('successful_attacks', 0) / total) * 100
        st.metric("Successful Attacks", stats.get('successful_attacks', 0), 
                 f"{success_rate:.1f}%", delta_color="inverse")
    
    with col3:
        block_rate = (stats.get('failed_attacks', 0) / total) * 100
        st.metric("Blocked Attacks", stats.get('failed_attacks', 0),
                 f"{block_rate:.1f}%", delta_color="normal")
    
    with col4:
        st.metric("Attack Types Tested", stats.get('unique_attacks', 0))


def add_custom_css():
    """Add professional CSS styling - AVAILABLE GLOBALLY"""
    st.markdown("""
    <style>
    /* Buttons */
    .stButton>button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 10px 24px;
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.3s;
    }
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
    }
    
    /* Info boxes - NOW AVAILABLE TO ALL COMPONENTS */
    .info-box {
        background: linear-gradient(135deg, #667eea15 0%, #764ba215 100%);
        border-left: 4px solid #667eea;
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
    }
    
    .success-box {
        background: linear-gradient(135deg, #51cf6615 0%, #48bb7815 100%);
        border-left: 4px solid #51cf66;
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
    }
    
    .danger-box {
        background: linear-gradient(135deg, #ff6b6b15 0%, #ee5a5a15 100%);
        border-left: 4px solid #ff6b6b;
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
    }
    
    .warning-box {
        background: linear-gradient(135deg, #ffd93d15 0%, #f9ca2415 100%);
        border-left: 4px solid #ffd93d;
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #667eea;
    }
    </style>
    """, unsafe_allow_html=True)