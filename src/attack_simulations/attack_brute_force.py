"""
COMPLETE FIX FOR ALL ATTACK FILES
Replace the specified sections in each file
"""

# ============================================================================
# FILE 1: attacks/attack_brute_force.py
# REPLACE ENTIRE FILE WITH THIS VERSION
# ============================================================================
"""
Brute Force Key Space Attack
Demonstrates computational infeasibility of exhaustive search
"""

import streamlit as st
import numpy as np
from .attack_visualizer import AttackVisualizer


class BruteForceAttack:
    """Brute force attack with computational analysis"""
    
    def __init__(self, channel, alice_keys, bob_keys, logger):
        self.channel = channel
        self.alice_keys = alice_keys
        self.bob_keys = bob_keys
        self.logger = logger
        self.visualizer = AttackVisualizer()
    
    def execute(self):
        """Execute brute force analysis"""
        st.markdown("### 💪 Brute Force Key Space Attack")
        
        with st.expander("📚 Cryptographic Key Space Theory", expanded=True):
            st.markdown("""
            **Kyber768 Security Parameters:**
            
            **Key Space:**
            ```
            Security level: NIST Level 3 (AES-192 equivalent)
            Classical security: 2^184 operations
            Quantum security: 2^92 operations (Grover's algorithm)
            Module dimension: n = 256, k = 3
            Modulus: q = 3329
            ```
            
            **Brute Force Complexity:**
            ```
            Classical: K = 2^184, Time at 10^12 ops/sec: 10^43 years
            Quantum (Grover): √K = 2^92, Still billions of years
            ```
            """)
        
        st.markdown("---")
        st.markdown("### 🎯 Computational Feasibility Analysis")
        
        computing_power = st.select_slider(
            "Attacker's computational resources:",
            options=[
                "Single PC (10^9 ops/sec)",
                "GPU Cluster (10^12 ops/sec)",
                "Supercomputer (10^18 ops/sec)",
                "All Earth's Computers (10^21 ops/sec)",
                "Hypothetical Quantum Computer (10^12 Grover ops/sec)"
            ],
            value="Supercomputer (10^18 ops/sec)"
        )
        
        parallelization = st.slider(
            "Parallelization factor:",
            min_value=1,
            max_value=1000000,
            value=1000,
            step=100,
            help="Number of parallel attack instances"
        )
        
        if st.button("🚀 Calculate Attack Feasibility", type="primary", key="brute_calc"):
            try:
                self._execute_analysis(computing_power, parallelization)
            except Exception as e:
                st.error(f"Error: {e}")
                st.exception(e)
    
    def _execute_analysis(self, power, parallel):
        """Execute comprehensive brute force analysis"""
        
        st.markdown("### 📊 Attack Computation Analysis")
        
        ops_map = {
            "Single PC (10^9 ops/sec)": 1e9,
            "GPU Cluster (10^12 ops/sec)": 1e12,
            "Supercomputer (10^18 ops/sec)": 1e18,
            "All Earth's Computers (10^21 ops/sec)": 1e21,
            "Hypothetical Quantum Computer (10^12 Grover ops/sec)": 1e12
        }
        
        ops_per_sec = ops_map[power] * parallel
        is_quantum = "Quantum" in power
        
        if is_quantum:
            total_ops = 2**92
            st.info("🔬 **Quantum Attack**: Using Grover's algorithm")
        else:
            total_ops = 2**184
            st.info("💻 **Classical Attack**: Exhaustive key search")
        
        seconds = total_ops / ops_per_sec
        years = seconds / (365.25 * 24 * 3600)
        universe_age = 13.8e9
        universes = years / universe_age
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Operations Required", f"2^{92 if is_quantum else 184}")
        with col2:
            st.metric("Computing Power", f"{ops_per_sec:.2e} ops/sec")
        with col3:
            st.metric("Time Required", 
                     f"{universes:.2e}× Universe Age" if universes >= 1 else f"{years:.2e} years")
        
        st.markdown("### 🔬 Detailed Time Analysis")
        
        st.code(f"""
Computational Parameters:
- Algorithm: {"Kyber768 with Grover" if is_quantum else "Kyber768 (Classical)"}
- Total operations: {total_ops:.2e}
- Operations per second: {ops_per_sec:.2e}
- Parallelization: {parallel:,} instances

Time Breakdown:
- Years: {years:.2e}
- Universe Ages: {universes:.2e}

CONCLUSION: COMPUTATIONALLY INFEASIBLE
        """, language="text")
        
        try:
            self._create_security_visualization(is_quantum)
        except Exception as e:
            st.warning(f"Visualization error: {e}")
        
        try:
            self._energy_cost_analysis(total_ops)
        except Exception as e:
            st.warning(f"Energy analysis error: {e}")
        
        # SUCCESS BOX - INLINE CSS
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #51cf6615 0%, #48bb7815 100%); 
                    border-left: 4px solid #51cf66; padding: 20px; border-radius: 8px; margin: 15px 0;">
        <h3 style="color: #51cf66; margin-top: 0;">✅ ATTACK COMPLETELY INFEASIBLE!</h3>
        <p><strong>Resource Level:</strong> {power} × {parallel:,} parallel instances</p>
        <p><strong>Time Required:</strong> {universes:.2e} × Age of Universe</p>
        <p><strong>Conclusion:</strong> Breaking Kyber768 would take {universes:.2e}× longer than the universe has existed.</p>
        <p><strong>🛡️ Security Guarantees:</strong></p>
        <ul>
            <li>Classical security: 2^184 operations (AES-192 equivalent)</li>
            <li>Quantum security: 2^92 operations (still infeasible)</li>
            <li>No known mathematical shortcuts</li>
            <li>Future-proof for 50+ years</li>
        </ul>
        </div>
        """, unsafe_allow_html=True)
        
        try:
            self.logger.log_attack({
                'attack_name': 'Brute Force Key Search',
                'attack_type': 'Cryptographic',
                'computing_power': power,
                'parallelization': parallel,
                'success': False,
                'time_required_years': float(years),
                'universe_ages': float(universes),
                'quantum': is_quantum
            })
        except Exception as e:
            st.warning(f"Logging error: {e}")
    
    def _create_security_visualization(self, is_quantum):
        """Create security visualization"""
        st.markdown("### 📊 Security Level Comparison")
        
        if is_quantum:
            algorithms = ['DES', 'AES-128', 'AES-192', 'RSA-2048\n(Shor)', 'Kyber768\n(Grover)', 'AES-256']
            classical_bits = [56, 128, 192, 112, 184, 256]
            quantum_bits = [28, 64, 96, 0, 92, 128]
            fig = self.visualizer.create_quantum_vs_classical(algorithms, classical_bits, quantum_bits)
        else:
            algorithms = ['DES\n(Broken)', 'AES-128', 'RSA-2048', 'AES-192', 'Kyber768', 'AES-256']
            security_bits = [56, 128, 112, 192, 184, 256]
            colors = ['red', 'yellow', 'orange', 'lightgreen', 'green', 'darkgreen']
            fig = self.visualizer.create_security_comparison(algorithms, security_bits, colors)
        
        st.plotly_chart(fig, use_container_width=True)
        
        st.info("""
        **Security Levels:**
        - < 80 bits: Broken/vulnerable
        - 80-112 bits: Deprecated
        - 128+ bits: Minimum recommended
        - 192+ bits: High security, future-proof
        """)
    
    def _energy_cost_analysis(self, operations):
        """Calculate energy cost"""
        st.markdown("### ⚡ Thermodynamic Energy Analysis")
        
        kT = 1.38e-23 * 300
        landauer_limit = kT * np.log(2)
        total_energy_j = operations * landauer_limit
        total_energy_kwh = total_energy_j / (3.6e6)
        
        world_energy_per_year = 580e12
        years_of_world_energy = total_energy_kwh / world_energy_per_year
        
        sun_output_per_sec = 3.828e26
        seconds_of_sun = total_energy_j / sun_output_per_sec
        years_of_sun = seconds_of_sun / (365.25 * 24 * 3600)
        
        mass_kg = total_energy_j / (3e8**2)
        earth_masses = mass_kg / 5.972e24
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Minimum Energy", f"{total_energy_kwh:.2e} kWh")
            st.metric("World Energy", f"{years_of_world_energy:.2e} years")
        with col2:
            st.metric("Sun's Output", f"{years_of_sun:.2e} years")
            st.metric("Mass-Energy", f"{earth_masses:.2e}× Earth Mass")
        
        # DANGER BOX - INLINE CSS
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #ff6b6b15 0%, #ee5a5a15 100%); 
                    border-left: 4px solid #ff6b6b; padding: 20px; border-radius: 8px; margin: 15px 0;">
        <h3 style="color: #ff6b6b; margin-top: 0;">⚡ THERMODYNAMIC IMPOSSIBILITY</h3>
        <p><strong>Energy requirement:</strong> {total_energy_kwh:.2e} kWh (theoretical minimum)</p>
        <p><strong>World energy:</strong> {years_of_world_energy:.2e} years of global production</p>
        <p><strong>Sun's energy:</strong> {years_of_sun:.2e} years of solar output</p>
        <p><strong>Mass conversion:</strong> {earth_masses:.2e}× Earth's mass</p>
        <p><strong>Conclusion:</strong> This is a <strong>physical impossibility</strong>, not just computational challenge.</p>
        </div>
        """, unsafe_allow_html=True)


# ============================================================================
# FILE 2: attacks/attack_cryptographic.py
# FIX THE IMPORT ON LINE ~134
# ============================================================================

# FIND THIS SECTION (around line 130-140):
"""
    def render(self):
        # ... other code ...
        
        if "Message Authentication" in attack_type:
            self.mac_forgery_attack()
        elif "Digital Signature" in attack_type:
            self.signature_forgery_attack()
        elif "Brute Force" in attack_type:
            from attack_brute_force import BruteForceAttack  # ❌ WRONG
            bf_attack = BruteForceAttack(self.channel, self.alice_keys, self.bob_keys, self.logger)
            bf_attack.execute()
"""

# REPLACE WITH:
"""
    def render(self):
        # ... other code ...
        
        if "Message Authentication" in attack_type:
            self.mac_forgery_attack()
        elif "Digital Signature" in attack_type:
            self.signature_forgery_attack()
        elif "Brute Force" in attack_type:
            from .attack_brute_force import BruteForceAttack  # ✅ FIXED
            bf_attack = BruteForceAttack(self.channel, self.alice_keys, self.bob_keys, self.logger)
            bf_attack.execute()
"""


# ============================================================================
# FILE 3: attacks/attack_analysis.py  
# FIX THE IMPORT ON LINE ~87
# ============================================================================

# FIND THIS SECTION (around line 85-90):
"""
        if "Matrix" in analysis_type:
            self.attack_success_matrix()
        elif "Classical vs Post-Quantum" in analysis_type:
            self.classical_vs_pqc()
        elif "Defense-in-Depth" in analysis_type:
            self.defense_in_depth()
        elif "Timeline" in analysis_type:
            self.security_timeline()
"""

# NO CHANGE NEEDED HERE - The brute force is called from attack_cryptographic.py
# But if you have it, change:
# from attack_brute_force import BruteForceAttack
# To:
# from .attack_brute_force import BruteForceAttack


# ============================================================================
# FILE 4: attacks/__init__.py
# MAKE SURE THIS FILE EXISTS WITH THIS CONTENT
# ============================================================================
"""
Post-Quantum Cryptography Attack Simulation Suite
"""

from .attacks import attack_simulations_page
from .attack_logger import AttackLogger
from .attack_visualizer import AttackVisualizer

__all__ = ['attack_simulations_page', 'AttackLogger', 'AttackVisualizer']


# ============================================================================
# FILE 5: attacks/attacks.py
# ENSURE CSS IS LOADED AT THE TOP
# ============================================================================

# The add_custom_css() function should be called FIRST in attack_simulations_page()
# Make sure it looks like this:

"""
def attack_simulations_page():
    # Apply CSS FIRST - this makes all CSS classes available
    add_custom_css()
    
    st.header("⚔️ Cryptographic Attack Simulation Suite")
    
    # ... rest of code ...
"""

# ============================================================================
# TESTING CHECKLIST
# ============================================================================
"""
After applying these fixes:

1. ✅ Restart your Streamlit app completely
2. ✅ Go to Key Generation page and generate keys
3. ✅ Go to Attacks page
4. ✅ Select "Cryptographic Attacks"
5. ✅ Select "Brute Force Key Space Attack"
6. ✅ Click the calculate button

If you still get errors, please share:
- The EXACT error message
- The full traceback
- Your folder structure
"""