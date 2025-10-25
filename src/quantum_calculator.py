"""
Quantum Threat Calculator page for Post-Quantum Cryptography Demo
Enhanced with comprehensive threat analysis

FILE: quantum_calculator.py
"""

import streamlit as st
import plotly.graph_objects as go
from datetime import datetime


# Algorithm security parameters (from your original calculator)
ALGORITHMS = {
    'RSA-1024': {'classical_bits': 80, 'quantum_bits': 0, 'key_size': 1024},
    'RSA-2048': {'classical_bits': 112, 'quantum_bits': 0, 'key_size': 2048},
    'RSA-3072': {'classical_bits': 128, 'quantum_bits': 0, 'key_size': 3072},
    'RSA-4096': {'classical_bits': 152, 'quantum_bits': 0, 'key_size': 4096},
    'ECC-256': {'classical_bits': 128, 'quantum_bits': 0, 'key_size': 256},
    'ECC-384': {'classical_bits': 192, 'quantum_bits': 0, 'key_size': 384},
    'AES-128': {'classical_bits': 128, 'quantum_bits': 64, 'key_size': 128},
    'AES-256': {'classical_bits': 256, 'quantum_bits': 128, 'key_size': 256},
    'Kyber512': {'classical_bits': 128, 'quantum_bits': 64, 'key_size': 800},
    'Kyber768': {'classical_bits': 192, 'quantum_bits': 96, 'key_size': 1184},
    'Kyber1024': {'classical_bits': 256, 'quantum_bits': 128, 'key_size': 1568},
    'Dilithium2': {'classical_bits': 128, 'quantum_bits': 64, 'key_size': 1312},
    'Dilithium3': {'classical_bits': 192, 'quantum_bits': 96, 'key_size': 1952},
    'Dilithium5': {'classical_bits': 256, 'quantum_bits': 128, 'key_size': 2592},
}

# Quantum computer development estimates
QC_MILESTONES = {
    2024: {'qubits': 1000, 'error_rate': 0.001, 'capability': 'Limited'},
    2027: {'qubits': 5000, 'error_rate': 0.0001, 'capability': 'Breaking RSA-1024 possible'},
    2030: {'qubits': 20000, 'error_rate': 0.00001, 'capability': 'Breaking RSA-2048 feasible'},
    2035: {'qubits': 100000, 'error_rate': 0.000001, 'capability': 'Breaking RSA-4096 possible'},
    2040: {'qubits': 1000000, 'error_rate': 0.0000001, 'capability': 'Full-scale quantum attacks'},
}


def quantum_calculator_page():
    """Main quantum threat calculator page"""
    st.header("🧮 Quantum Threat Calculator")
    
    st.markdown("""
    <div class="info-box">
        Calculate when various cryptographic algorithms will be vulnerable to quantum computers
    </div>
    """, unsafe_allow_html=True)
    
    # Tabs for different analyses
    tab1, tab2, tab3, tab4 = st.tabs([
        "🎯 Threat Calculator", 
        "📊 Algorithm Comparison",
        "⏱️ QC Timeline",
        "🕵️ Harvest Now, Decrypt Later"
    ])
    
    with tab1:
        _threat_calculator()
    
    with tab2:
        _algorithm_comparison()
    
    with tab3:
        _quantum_timeline()
    
    with tab4:
        _harvest_attack_analysis()


def _threat_calculator():
    """Interactive threat calculator"""
    st.subheader("Individual Algorithm Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        algorithm = st.selectbox(
            "Select Algorithm:",
            list(ALGORITHMS.keys())
        )
    
    with col2:
        data_lifetime = st.slider(
            "Data must remain secret for (years):", 
            1, 50, 10
        )
    
    if st.button("🔍 Analyze Threat", type="primary"):
        _analyze_algorithm_threat(algorithm, data_lifetime)


def _analyze_algorithm_threat(algorithm, data_lifetime):
    """Analyze threat for specific algorithm"""
    algo = ALGORITHMS[algorithm]
    current_year = datetime.now().year
    target_year = current_year + data_lifetime
    
    # Display algorithm info
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Key Size", f"{algo['key_size']} bits")
    with col2:
        st.metric("Classical Security", f"{algo['classical_bits']} bits")
    with col3:
        st.metric("Quantum Security", f"{algo['quantum_bits']} bits")
    
    # Determine break year
    break_year = _estimate_break_year(algorithm, algo)
    
    # Display threat assessment
    if break_year is None:
        st.markdown(f"""
        <div class="success-box">
            <h3>✓ QUANTUM-SAFE ALGORITHM</h3>
            <strong>{algorithm}</strong> is resistant to quantum attacks!<br>
            Your data will remain secure for {data_lifetime} years and beyond.
        </div>
        """, unsafe_allow_html=True)
    elif target_year >= break_year:
        years_until = break_year - current_year
        st.markdown(f"""
        <div class="danger-box">
            <h3>⚠️ CRITICAL THREAT</h3>
            <strong>Algorithm:</strong> {algorithm}<br>
            <strong>Estimated break year:</strong> {break_year}<br>
            <strong>Data needs protection until:</strong> {target_year}<br>
            <strong>Time until vulnerable:</strong> {years_until} years<br>
            <br>
            <strong>⚠️ YOUR DATA WILL BE AT RISK!</strong><br>
            <strong>RECOMMENDATION: Migrate to post-quantum cryptography IMMEDIATELY!</strong>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="info-box">
            <h3>✓ Currently Secure</h3>
            <strong>{algorithm}</strong> should be secure until ~{break_year}<br>
            Your data needs protection until {target_year}<br>
            <br>
            You have time, but start planning migration to PQC now.
        </div>
        """, unsafe_allow_html=True)
    
    # Timeline visualization
    _display_threat_timeline(algorithm, break_year, target_year)


def _estimate_break_year(algorithm_name, algo):
    """Estimate when an algorithm will be practically breakable"""
    if algo['quantum_bits'] == 0:
        # Vulnerable to Shor's algorithm
        if 'RSA-1024' in algorithm_name:
            return 2027
        elif 'RSA-2048' in algorithm_name:
            return 2030
        elif 'RSA-3072' in algorithm_name:
            return 2033
        elif 'RSA-4096' in algorithm_name:
            return 2035
        elif 'ECC-256' in algorithm_name:
            return 2028
        elif 'ECC-384' in algorithm_name:
            return 2032
        else:
            return 2030
    else:
        # Post-quantum algorithms
        if algo['quantum_bits'] >= 128:
            return None  # Not breakable in foreseeable future
        elif algo['quantum_bits'] >= 96:
            return 2060  # Very far future
        elif algo['quantum_bits'] >= 64:
            return 2050
        else:
            return 2040


def _display_threat_timeline(algorithm, break_year, target_year):
    """Display timeline visualization"""
    years = list(range(2024, 2051))
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
        line=dict(color='red' if break_year else 'green', width=3)
    ))
    
    fig.update_layout(
        title=f'Quantum Threat Timeline for {algorithm}',
        xaxis_title='Year',
        yaxis_title='Risk Level (%)',
        yaxis_range=[0, 110],
        height=400
    )
    
    if target_year:
        fig.add_vline(
            x=target_year, 
            line_dash="dash", 
            annotation_text=f"Data Expiry ({target_year})",
            line_color="blue"
        )
    
    if break_year:
        fig.add_vline(
            x=break_year,
            line_dash="dash",
            annotation_text=f"Quantum Threat ({break_year})",
            line_color="red"
        )
    
    st.plotly_chart(fig, use_container_width=True)


def _algorithm_comparison():
    """Compare all algorithms"""
    st.subheader("📊 Security Comparison Table")
    
    st.markdown("### Classical vs Quantum Security")
    
    # Create comparison table
    comparison_data = []
    for name, algo in sorted(ALGORITHMS.items(), key=lambda x: x[1]['classical_bits'], reverse=True):
        status = "🔴 Vulnerable" if algo['quantum_bits'] == 0 else (
            "🟢 Quantum-Safe" if algo['quantum_bits'] >= 96 else "🟡 Moderate"
        )
        
        comparison_data.append({
            'Algorithm': name,
            'Key Size': f"{algo['key_size']} bits",
            'Classical Security': f"{algo['classical_bits']} bits",
            'Quantum Security': f"{algo['quantum_bits']} bits" if algo['quantum_bits'] > 0 else "BROKEN",
            'Status': status
        })
    
    st.table(comparison_data)
    
    # Visualization
    _display_security_comparison_chart()


def _display_security_comparison_chart():
    """Display security level comparison chart"""
    st.markdown("### Security Bits Comparison")
    
    algorithms = list(ALGORITHMS.keys())
    classical = [ALGORITHMS[a]['classical_bits'] for a in algorithms]
    quantum = [ALGORITHMS[a]['quantum_bits'] for a in algorithms]
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        name='Classical Security',
        x=algorithms,
        y=classical,
        marker_color='lightblue'
    ))
    
    fig.add_trace(go.Bar(
        name='Quantum Security',
        x=algorithms,
        y=quantum,
        marker_color='darkblue'
    ))
    
    fig.update_layout(
        title='Security Bits: Classical vs Quantum Attacks',
        xaxis_title='Algorithm',
        yaxis_title='Security Bits',
        barmode='group',
        height=500,
        xaxis_tickangle=-45
    )
    
    st.plotly_chart(fig, use_container_width=True)


def _quantum_timeline():
    """Display quantum computer development timeline"""
    st.subheader("⏱️ Quantum Computer Development Timeline")
    
    st.markdown("""
    Projected milestones in quantum computing capability based on current research trends:
    """)
    
    current_year = datetime.now().year
    
    for year, data in sorted(QC_MILESTONES.items()):
        years_away = year - current_year
        
        if years_away > 0:
            time_label = f"**{year}** ({years_away} years from now)"
        elif years_away == 0:
            time_label = f"**{year}** (This year)"
        else:
            time_label = f"**{year}** ({abs(years_away)} years ago)"
        
        with st.expander(f"{time_label} - {data['capability']}"):
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Qubits", f"~{data['qubits']:,}")
            with col2:
                st.metric("Error Rate", f"{data['error_rate']}")
            with col3:
                st.metric("Capability", data['capability'])


def _harvest_attack_analysis():
    """Analyze 'Harvest Now, Decrypt Later' threat"""
    st.subheader("🕵️ 'Harvest Now, Decrypt Later' Threat")
    
    st.warning("""
    **Critical Threat Scenario:**
    
    1. **TODAY (2024):** Attacker captures and stores your encrypted communications
    2. **2030+:** Quantum computers become available
    3. **FUTURE:** Attacker decrypts your historical data
    4. **IMPACT:** Secrets from years ago are exposed!
    """)
    
    st.markdown("### 🎯 Data Protection Timeline Analysis")
    
    data_lifetimes = [5, 10, 15, 20, 25, 30]
    current_year = datetime.now().year
    
    timeline_data = []
    for lifetime in data_lifetimes:
        target_year = current_year + lifetime
        
        if target_year >= 2030:
            rsa_status = "🔴 AT RISK"
            rsa_color = "danger"
        else:
            rsa_status = "🟡 Probably OK"
            rsa_color = "warning"
        
        timeline_data.append({
            'Data Lifetime': f"{lifetime} years",
            'Target Year': target_year,
            'RSA-2048': rsa_status,
            'Kyber768': "🟢 SECURE"
        })
    
    st.table(timeline_data)
    
    st.markdown("### 💡 Recommendations by Data Type")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **🔴 Migrate to PQC NOW:**
        - Medical records (70+ years)
        - Government secrets (50+ years)
        - Financial data (10+ years)
        - Legal documents (20+ years)
        """)
    
    with col2:
        st.markdown("""
        **🟡 Consider PQC Migration:**
        - Personal messages (<5 years)
        - Session data (hours/days)
        - Temporary credentials
        - Short-term communications
        """)
    
    st.error("""
    **⚠️ Key Insight:** If your data needs to stay secret for 10+ years, 
    you MUST use post-quantum cryptography NOW!
    """)