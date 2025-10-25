"""
Post-Quantum Cryptography Attack Simulation Suite
Professional implementation with mathematical proofs and visualizations

FILE: attacks.py
Main entry point for attack simulations
"""

import streamlit as st
import time
from .attack_cryptographic import CryptographicAttacks
from .attack_protocol import ProtocolAttacks
from .attack_analysis import AttackAnalysis
from .attack_visualizer import AttackVisualizer
from .attack_logger import AttackLogger


def attack_simulations_page():
    """Main attack simulations page - ENTRY POINT"""
    st.header("⚔️ Cryptographic Attack Simulation Suite")
    
    # Initialize attack logger
    if 'attack_logger' not in st.session_state:
        st.session_state.attack_logger = AttackLogger()
    
    # Check if keys are generated
    if 'alice_keys' not in st.session_state or 'bob_keys' not in st.session_state:
        st.warning("⚠️ Please generate keys first in the Key Generation page!")
        return
    
    if not st.session_state.alice_keys or not st.session_state.bob_keys:
        st.warning("⚠️ Please generate keys first in the Key Generation page!")
        return
    
    # Check if channel exists
    if 'channel' not in st.session_state:
        st.error("❌ Communication channel not initialized!")
        return
    
    # Display professional header with statistics
    display_attack_dashboard()
    
    st.markdown("---")
    
    # Main navigation with improved descriptions
    attack_category = st.radio(
        "**Select Attack Category:**",
        ["🛡️ Cryptographic Attacks (Algorithm-Level)", 
         "⚠️ Protocol Attacks (System-Level)",
         "📊 Comprehensive Analysis & Comparison"],
        horizontal=False,
        help="Choose attack category to explore different security aspects"
    )
    
    st.markdown("---")
    
    # Route to appropriate section with proper class instances
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


def display_attack_dashboard():
    """Professional statistics dashboard"""
    st.markdown("""
    <style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        text-align: center;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .metric-value {
        font-size: 2.5em;
        font-weight: bold;
        margin: 10px 0;
    }
    .metric-label {
        font-size: 0.9em;
        opacity: 0.9;
    }
    </style>
    """, unsafe_allow_html=True)
    
    logger = st.session_state.attack_logger
    
    try:
        stats = logger.get_statistics()
    except Exception as e:
        st.error(f"Error loading statistics: {e}")
        stats = {
            'total_attacks': 0,
            'successful_attacks': 0,
            'failed_attacks': 0,
            'unique_attacks': 0
        }
    
    st.markdown("### 📊 Attack Simulation Statistics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Simulations",
            stats.get('total_attacks', 0),
            help="Total number of attack simulations executed"
        )
    
    with col2:
        total = max(stats.get('total_attacks', 1), 1)
        success_rate = (stats.get('successful_attacks', 0) / total) * 100
        st.metric(
            "Successful Attacks",
            stats.get('successful_attacks', 0),
            f"{success_rate:.1f}%",
            delta_color="inverse"
        )
    
    with col3:
        block_rate = (stats.get('failed_attacks', 0) / total) * 100
        st.metric(
            "Blocked Attacks",
            stats.get('failed_attacks', 0),
            f"{block_rate:.1f}%",
            delta_color="normal"
        )
    
    with col4:
        st.metric(
            "Attack Types Tested",
            stats.get('unique_attacks', 0),
            help="Number of different attack vectors tested"
        )
    
    # Simplified recent activity - only show if we have attacks
    total_attacks = stats.get('total_attacks', 0)
    if total_attacks > 0:
        st.info(f"✓ {total_attacks} attack simulation(s) completed. View detailed results below.")


# Add professional styling
def add_custom_css():
    """Add professional CSS styling"""
    st.markdown("""
    <style>
    /* Professional color scheme */
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
    
    /* Info boxes */
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
    
    /* Code blocks */
    .stCodeBlock {
        background: #1e1e1e;
        border-radius: 8px;
        border: 1px solid #333;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #667eea;
    }
    
    /* Metrics */
    [data-testid="stMetricValue"] {
        font-size: 2em;
        color: #667eea;
    }
    </style>
    """, unsafe_allow_html=True)

add_custom_css()