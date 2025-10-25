"""
Comparative Analysis and Visualization
Comprehensive security analysis across all attack vectors

FILE: attack_analysis.py
"""

import streamlit as st
import pandas as pd
from .attack_visualizer import AttackVisualizer


class AttackAnalysis:
    """Comprehensive attack analysis and comparison"""
    
    def __init__(self, logger):
        self.logger = logger
        self.visualizer = AttackVisualizer()
    
    def render(self):
        """Main render method"""
        st.subheader("📊 Comprehensive Security Analysis")
        
        analysis_type = st.selectbox(
            "**Choose Analysis Type:**",
            [
                "🎯 Attack Success Matrix",
                "⚔️ Classical vs Post-Quantum Comparison",
                "🛡️ Defense-in-Depth Analysis",
                "📈 Security Timeline & Risk Assessment"
            ]
        )
        
        st.markdown("---")
        
        if "Matrix" in analysis_type:
            self.attack_success_matrix()
        elif "Classical vs Post-Quantum" in analysis_type:
            self.classical_vs_pqc()
        elif "Defense-in-Depth" in analysis_type:
            self.defense_in_depth()
        elif "Timeline" in analysis_type:
            self.security_timeline()
    
    def attack_success_matrix(self):
        """Comprehensive attack success matrix"""
        st.markdown("### 🎯 Attack Success Matrix")
        
        st.info("""
        This matrix shows which attacks succeed (✓) or fail (✗) against different 
        security configurations. It demonstrates why multiple security layers are essential.
        """)
        
        # Create comprehensive matrix
        matrix_data = {
            'Attack Type': [
                "Message Tampering",
                "Signature Forgery",
                "Brute Force Key Search",
                "Ciphertext-Only Attack",
                "Replay Attack",
                "Man-in-the-Middle",
                "Downgrade Attack",
                "Timing Side-Channel"
            ],
            'No\nCrypto': ['✓', '✓', '✓', '✓', '✓', '✓', '✓', '✓'],
            'Classical\nCrypto': ['✗', '✗', '✗', '✗', '✓', '✓', '✓', '✓'],
            'Post-Quantum\nCrypto': ['✗', '✗', '✗', '✗', '✓', '✓', '✓', '✓'],
            'PQC +\nPKI': ['✗', '✗', '✗', '✗', '✓', '✗', '✓', '✓'],
            'PQC + PKI +\nNonce/Time': ['✗', '✗', '✗', '✗', '✗', '✗', '✗', '✓'],
            'Complete\nSolution*': ['✗', '✗', '✗', '✗', '✗', '✗', '✗', '✗']
        }
        
        df = pd.DataFrame(matrix_data)
        
        # Display as styled table
        st.markdown("**Security System Effectiveness:**")
        st.markdown("*✓ = Attack Succeeds | ✗ = Attack Blocked*")
        
        # Style the dataframe
        def style_cell(val):
            if val == '✓':
                return 'background-color: #ff6b6b; color: white; font-weight: bold; font-size: 18px; text-align: center;'
            elif val == '✗':
                return 'background-color: #51cf66; color: white; font-weight: bold; font-size: 18px; text-align: center;'
            return 'text-align: center;'
        
        styled_df = df.style.applymap(style_cell, subset=df.columns[1:])
        st.dataframe(styled_df, use_container_width=True, height=400)
        
        st.caption("*Complete Solution = PQC + PKI + Nonce/Timestamp + Constant-Time Implementation + Protocol Enforcement")
        
        # Calculate effectiveness
        st.markdown("---")
        st.markdown("### 📊 System Effectiveness Analysis")
        
        systems = list(matrix_data.keys())[1:]
        blocked_counts = [matrix_data[sys].count('✗') for sys in systems]
        total_attacks = 8
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                "Post-Quantum Crypto Only",
                f"{blocked_counts[2]}/{total_attacks}",
                f"{(blocked_counts[2]/total_attacks)*100:.0f}% effective"
            )
        
        with col2:
            st.metric(
                "PQC + PKI + Nonce",
                f"{blocked_counts[4]}/{total_attacks}",
                f"{(blocked_counts[4]/total_attacks)*100:.0f}% effective"
            )
        
        with col3:
            st.metric(
                "Complete Solution",
                f"{blocked_counts[5]}/{total_attacks}",
                f"{(blocked_counts[5]/total_attacks)*100:.0f}% effective"
            )
        
        # Bar chart
        import plotly.graph_objects as go
        
        fig = go.Figure()
        
        colors = ['red', 'orange', 'yellow', 'lightgreen', 'green', 'darkgreen']
        
        fig.add_trace(go.Bar(
            x=systems,
            y=blocked_counts,
            marker_color=colors,
            text=[f"{b}/{total_attacks}" for b in blocked_counts],
            textposition='auto',
            hovertemplate='<b>%{x}</b><br>Blocks: %{y}/8 attacks<br><extra></extra>'
        ))
        
        fig.update_layout(
            title='Attacks Blocked by Security System',
            xaxis_title='Security Configuration',
            yaxis_title='Attacks Blocked (out of 8)',
            yaxis_range=[0, 8.5],
            showlegend=False,
            height=450
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Key insights
        st.markdown("---")
        st.markdown("### 💡 Key Insights")
        
        st.success("""
        **Critical Findings:**
        
        1. **Post-Quantum Cryptography Alone: 50% Effective**
           - Blocks: Tampering, Forgery, Brute Force, Ciphertext attacks
           - Vulnerable to: Replay, MITM, Downgrade, Timing attacks
           - **Lesson:** Algorithm security ≠ System security
        
        2. **Adding PKI: 62.5% Effective**
           - Additionally blocks: Man-in-the-Middle attacks
           - Still vulnerable to: Replay, Downgrade, Timing
           - **Lesson:** Key authentication is essential
        
        3. **Adding Nonce/Timestamps: 87.5% Effective**
           - Additionally blocks: Replay attacks
           - Still vulnerable to: Downgrade, Timing
           - **Lesson:** Protocol-level protections required
        
        4. **Complete Solution: 100% Effective**
           - Requires: PQC + PKI + Nonces + Constant-Time + Enforcement
           - Blocks: ALL attacks demonstrated
           - **Lesson:** Defense-in-depth is mandatory
        
        **Professional Security Principle:**
        ```
        Security = Σ(Cryptography, Protocols, Implementation, Operations)
        
        Strong cryptography is necessary but not sufficient.
        Real-world security requires multiple complementary layers.
        ```
        """)
        
        # Heatmap visualization
        st.markdown("---")
        st.markdown("### 🔥 Attack Success Heatmap")
        
        fig_heatmap = self.visualizer.create_attack_success_matrix_heatmap(matrix_data)
        st.plotly_chart(fig_heatmap, use_container_width=True)
    
    def classical_vs_pqc(self):
        """Compare classical and post-quantum cryptography"""
        st.markdown("### ⚔️ Classical vs Post-Quantum Cryptography")
        
        st.markdown("""
        <div class="info-box">
        Comprehensive comparison of cryptographic approaches across multiple dimensions:
        security, performance, implementation complexity, and future-proofing.
        </div>
        """, unsafe_allow_html=True)
        
        # Side-by-side comparison
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🔐 Classical Cryptography (RSA-2048)")
            st.markdown("""
            **Algorithms:**
            - Key Exchange: RSA-2048 / ECDH
            - Digital Signatures: RSA-2048 / ECDSA
            - Symmetric Encryption: AES-256
            
            **Security Guarantees:**
            - ✓ Secure vs classical computers
            - ✗ Vulnerable to quantum computers (Shor's algorithm)
            - ⚠️ Estimated break year: 2030-2035
            - Security level: 112-bit (classical)
            
            **Mathematical Basis:**
            - Integer factorization (RSA)
            - Discrete logarithm (ECDH, ECDSA)
            - Both solvable by Shor's quantum algorithm
            
            **Performance:**
            - RSA Key gen: ~50-100 ms
            - RSA Encryption: ~1 ms
            - RSA Decryption: ~5-10 ms
            - Signature: ~5-10 ms
            - Verification: ~1 ms
            
            **Key Sizes:**
            - RSA-2048 public: 294 bytes
            - RSA-2048 private: 1,192 bytes
            - ECDSA-256 public: 64 bytes
            - ECDSA-256 private: 32 bytes
            
            **Advantages:**
            - ✓ Mature, well-studied (40+ years)
            - ✓ Widely deployed
            - ✓ Small key sizes (ECDSA)
            - ✓ Hardware acceleration available
            
            **Disadvantages:**
            - ✗ Quantum vulnerable
            - ✗ "Harvest now, decrypt later" threat
            - ✗ RSA slow for key operations
            - ✗ No future-proofing
            """)
        
        with col2:
            st.markdown("#### 🛡️ Post-Quantum Cryptography (Kyber768)")
            st.markdown("""
            **Algorithms:**
            - Key Exchange: Kyber768 (Module-LWE)
            - Digital Signatures: Dilithium3 (Module-LWE/SIS)
            - Symmetric Encryption: AES-256
            
            **Security Guarantees:**
            - ✓ Secure vs classical computers
            - ✓ Secure vs quantum computers
            - ✓ Future-proof (50+ years)
            - Security level: 184-bit (classical), 92-bit (quantum)
            
            **Mathematical Basis:**
            - Lattice problems (LWE, SIS)
            - No efficient quantum algorithms known
            - Worst-case to average-case reduction
            
            **Performance:**
            - Kyber Key gen: ~0.5 ms (100× faster!)
            - Kyber Encaps: ~0.3 ms
            - Kyber Decaps: ~0.4 ms
            - Dilithium Sign: ~1-2 ms
            - Dilithium Verify: ~0.5 ms
            
            **Key Sizes:**
            - Kyber768 public: 1,184 bytes
            - Kyber768 private: 2,400 bytes
            - Dilithium3 public: 1,952 bytes
            - Dilithium3 signature: 3,293 bytes
            
            **Advantages:**
            - ✓ Quantum resistant
            - ✓ Fast key generation
            - ✓ Fast encryption/decryption
            - ✓ NIST standardized
            
            **Disadvantages:**
            - ⚠️ Larger keys/signatures
            - ⚠️ Newer (less deployment experience)
            - ⚠️ Implementation complexity
            - ⚠️ Side-channel considerations
            """)
        
        # Detailed comparison tables
        st.markdown("---")
        st.markdown("### 📊 Detailed Performance Comparison")
        
        perf_data = {
            'Operation': ['Key Generation', 'Encryption', 'Decryption', 'Signing', 'Verification'],
            'RSA-2048 (ms)': [75, 1, 7.5, 7.5, 1],
            'Kyber768 (ms)': [0.5, 0.3, 0.4, 1.5, 0.5],
            'Speedup': ['150×', '3.3×', '18.8×', '5×', '2×']
        }
        
        st.dataframe(pd.DataFrame(perf_data), use_container_width=True)
        
        # Security comparison
        st.markdown("### 🔒 Security Level Comparison")
        
        sec_data = {
            'Algorithm': ['RSA-2048', 'ECDSA-256', 'Kyber768', 'Dilithium3'],
            'Classical Security (bits)': [112, 128, 184, 128],
            'Quantum Security (bits)': [0, 0, 92, 128],
            'NIST Level': ['N/A', 'N/A', '3', '3'],
            'Quantum Resistant': ['✗', '✗', '✓', '✓']
        }
        
        st.dataframe(pd.DataFrame(sec_data), use_container_width=True)
        
        # Radar chart comparison
        st.markdown("---")
        st.markdown("### 📈 Multi-Dimensional Security Analysis")
        
        categories = ['Classical Security', 'Quantum Security', 'Performance', 'Maturity']
        pqc_scores = [95, 90, 95, 70]  # PQC strong in all but maturity
        classical_scores = [85, 0, 80, 100]  # Classical strong in maturity, zero quantum
        
        fig = self.visualizer.create_radar_chart(categories, pqc_scores, classical_scores)
        fig.data[0].name = 'Post-Quantum (Kyber768/Dilithium3)'
        fig.data[1].name = 'Classical (RSA-2048/ECDSA)'
        st.plotly_chart(fig, use_container_width=True)
        
        # Interactive threat calculator
        st.markdown("---")
        st.markdown("### 🎯 Personalized Risk Assessment")
        
        st.markdown("**Calculate your cryptographic risk:**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            quantum_year = st.slider(
                "When will quantum computers break RSA?",
                min_value=2025,
                max_value=2040,
                value=2030,
                help="Conservative estimates: 2030-2035"
            )
        
        with col2:
            data_lifetime = st.slider(
                "How long must your data stay secret?",
                min_value=1,
                max_value=50,
                value=10,
                help="Years from now"
            )
        
        current_year = 2024
        data_expiry = current_year + data_lifetime
        
        # Risk assessment
        if data_expiry >= quantum_year:
            years_at_risk = data_expiry - quantum_year
            st.markdown(f"""
            <div class="danger-box">
            <h3>⚠️ HIGH RISK - RSA-2048 INSUFFICIENT!</h3>
            <strong>Data must remain secret until:</strong> {data_expiry}<br>
            <strong>Quantum threat arrives:</strong> {quantum_year}<br>
            <strong>Years at risk:</strong> {years_at_risk} years<br>
            <br>
            <strong>⚠️ YOUR DATA WILL BE COMPROMISED!</strong><br>
            <br>
            <strong>Recommended Actions:</strong><br>
            1. 🚨 Migrate to post-quantum cryptography IMMEDIATELY<br>
            2. 📋 Audit all systems using RSA/ECDH/ECDSA<br>
            3. 🔄 Plan phased migration to Kyber768/Dilithium3<br>
            4. 📊 Prioritize high-value, long-lived data<br>
            5. 🛡️ Consider hybrid classical+PQC during transition
            </div>
            """, unsafe_allow_html=True)
        else:
            safety_margin = quantum_year - data_expiry
            st.markdown(f"""
            <div class="success-box">
            <h3>✓ CURRENTLY SAFE - But Plan Ahead!</h3>
            <strong>Data must remain secret until:</strong> {data_expiry}<br>
            <strong>Quantum threat arrives:</strong> {quantum_year}<br>
            <strong>Safety margin:</strong> {safety_margin} years<br>
            <br>
            <strong>Status:</strong> Your data will expire before quantum threat<br>
            <br>
            <strong>Recommended Actions:</strong><br>
            1. ✓ Current RSA-2048 is sufficient for this data<br>
            2. 📋 But start planning PQC migration for future systems<br>
            3. 🔄 Implement PQC for new deployments<br>
            4. 📚 Train team on post-quantum cryptography<br>
            5. 🧪 Test PQC in non-critical systems first
            </div>
            """, unsafe_allow_html=True)
        
        # Timeline visualization
        years = list(range(2024, 2051))
        rsa_security = [100 if y < quantum_year else 0 for y in years]
        pqc_security = [100] * len(years)
        
        fig_timeline = self.visualizer.create_attack_timeline(
            years, rsa_security, pqc_security, quantum_year, data_expiry
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
        
        # Migration guidance
        st.markdown("---")
        st.markdown("### 🚀 Migration Strategy")
        
        st.info("""
        **Phased Migration Approach:**
        
        **Phase 1: Assessment (3-6 months)**
        - Inventory all cryptographic systems
        - Identify RSA/ECDH/ECDSA usage
        - Assess data sensitivity and lifetime
        - Prioritize critical systems
        
        **Phase 2: Testing (6-12 months)**
        - Deploy PQC in test environments
        - Performance testing and benchmarking
        - Integration testing with existing systems
        - Security audit of PQC implementation
        
        **Phase 3: Hybrid Deployment (12-24 months)**
        - Deploy hybrid classical+PQC
        - Maintain backward compatibility
        - Gradual rollout to production
        - Monitor performance and stability
        
        **Phase 4: Full Migration (24-36 months)**
        - Complete transition to PQC
        - Deprecate classical-only systems
        - Update all certificates and keys
        - Employee training and documentation
        
        **Critical:** Don't wait for quantum computers to exist!
        "Harvest now, decrypt later" attacks are happening today.
        """)
    
    def defense_in_depth(self):
        """Defense in depth analysis"""
        st.markdown("### 🛡️ Defense-in-Depth Analysis")
        
        st.markdown("""
        <div class="info-box">
        <strong>Defense-in-Depth Principle:</strong><br>
        Security is achieved through multiple independent layers of protection. 
        If one layer fails, others continue to provide security.
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        st.markdown("### 🔐 Security Layers Configuration")
        
        st.markdown("**Select active security layers:**")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            layer1 = st.checkbox("🔐 Encryption (AES-256-GCM)", value=True, key="def1")
            layer2 = st.checkbox("✍️ Digital Signatures (Dilithium3)", value=True, key="def2")
            layer3 = st.checkbox("🔑 Post-Quantum KEM (Kyber768)", value=True, key="def3")
        
        with col2:
            layer4 = st.checkbox("📜 PKI/Certificates", value=False, key="def4")
            layer5 = st.checkbox("🔄 Nonce/Timestamp Tracking", value=False, key="def5")
            layer6 = st.checkbox("⏱️ Constant-Time Implementation", value=False, key="def6")
        
        with col3:
            layer7 = st.checkbox("🚫 Strict Protocol Enforcement", value=False, key="def7")
            layer8 = st.checkbox("📊 Anomaly Detection", value=False, key="def8")
            layer9 = st.checkbox("🔒 Hardware Security (HSM)", value=False, key="def9")
        
        # Calculate protection
        protections = {
            'Message Tampering': layer2,  # Signatures
            'Signature Forgery': layer2 and layer3,  # Signatures + PQC
            'Brute Force': layer1 and layer3,  # Encryption + large keyspace
            'Ciphertext Attack': layer1,  # Strong encryption
            'Replay Attack': layer5,  # Nonce tracking
            'MITM': layer4,  # PKI
            'Downgrade': layer7,  # Protocol enforcement
            'Timing Attack': layer6  # Constant-time
        }
        
        blocked = sum(protections.values())
        total = len(protections)
        active_layers = sum([layer1, layer2, layer3, layer4, layer5, layer6, layer7, layer8, layer9])
        
        # Summary metrics
        st.markdown("---")
        st.markdown("### 📊 Protection Summary")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                "Active Layers",
                f"{active_layers}/9",
                help="Number of security layers enabled"
            )
        
        with col2:
            st.metric(
                "Attacks Blocked",
                f"{blocked}/{total}",
                f"{(blocked/total*100):.0f}%"
            )
        
        with col3:
            if blocked == total:
                st.metric("Security Status", "✅ Complete", "All attacks blocked")
            elif blocked >= 6:
                st.metric("Security Status", "⚠️ Good", f"{total-blocked} gaps")
            else:
                st.metric("Security Status", "❌ Insufficient", f"{total-blocked} gaps")
        
        # Visualization
        fig = self.visualizer.create_defense_layers_chart(protections, blocked)
        st.plotly_chart(fig, use_container_width=True)
        
        # Recommendations
        if blocked < total:
            st.markdown("---")
            st.markdown("### 💡 Recommendations")
            
            st.warning(f"**{total - blocked} vulnerabilities remain!**")
            
            recommendations = []
            
            if not layer4:
                recommendations.append("🔐 **Enable PKI/Certificates** to prevent Man-in-the-Middle attacks")
            if not layer5:
                recommendations.append("🔄 **Implement Nonce/Timestamp tracking** to prevent Replay attacks")
            if not layer6:
                recommendations.append("⏱️ **Use Constant-Time implementations** to prevent Timing attacks")
            if not layer7:
                recommendations.append("🚫 **Enforce Strict Protocol policies** to prevent Downgrade attacks")
            if not layer8:
                recommendations.append("📊 **Deploy Anomaly Detection** for real-time threat monitoring")
            if not layer9:
                recommendations.append("🔒 **Consider Hardware Security Modules** for key protection")
            
            for rec in recommendations:
                st.markdown(f"- {rec}")
        else:
            st.success("""
            ### ✅ Complete Security Posture Achieved!
            
            All demonstrated attack vectors are blocked by your current configuration.
            Continue to:
            - Monitor for new attack techniques
            - Keep cryptographic libraries updated
            - Regular security audits
            - Employee security training
            """)
    
    def security_timeline(self):
        """Security timeline and risk assessment"""
        st.markdown("### 📈 Security Timeline & Future Risk Assessment")
        
        st.markdown("""
        <div class="info-box">
        Analyze how security guarantees evolve over time and assess long-term risks.
        </div>
        """, unsafe_allow_html=True)
        
        # Historical context
        st.markdown("---")
        st.markdown("### 📜 Historical Cryptographic Timeline")
        
        timeline_data = {
            'Year': [1977, 1997, 1999, 2001, 2015, 2016, 2024, 2030, 2035],
            'Event': [
                'RSA invented',
                'DES broken (practical)',
                'DES broken (< 1 day)',
                'AES standardized',
                'SHA-1 collision (theoretical)',
                'SHA-1 collision (practical)',
                'NIST PQC standards',
                'Quantum computers (est.)',
                'RSA broken (est.)'
            ],
            'Impact': [
                'Revolution',
                'Security crisis',
                'Standard obsolete',
                'New standard',
                'Warning signs',
                'Migration needed',
                'Future-proofing',
                'Classical crypto ends',
                'PQC era begins'
            ]
        }
        
        st.dataframe(pd.DataFrame(timeline_data), use_container_width=True)
        
        st.warning("""
        **Key Pattern:** Cryptographic algorithms have a limited lifespan. Plan for:
        - Algorithm deployment: ~40 years lifetime expected
        - Active use: ~20-30 years typical
        - Phase-out period: ~10 years
        - **Lesson:** Start PQC migration NOW, even if quantum computers are years away!
        """)
        
        # Future projection
        st.markdown("---")
        st.markdown("### 🔮 Future Security Projection")
        
        st.markdown("**Configure your scenario:**")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            quantum_optimistic = st.number_input("Optimistic (years)", min_value=2025, max_value=2050, value=2028)
        with col2:
            quantum_realistic = st.number_input("Realistic (years)", min_value=2025, max_value=2050, value=2032)
        with col3:
            quantum_pessimistic = st.number_input("Pessimistic (years)", min_value=2025, max_value=2050, value=2038)
        
        # Risk analysis
        st.markdown("### ⚠️ Risk Analysis by Data Type")
        
        data_types = {
            'Data Type': [
                'Session keys (ephemeral)',
                'TLS certificates (1-2 years)',
                'Personal health records (10 years)',
                'Financial records (7-10 years)',
                'State secrets (30+ years)',
                'Identity documents (lifetime)',
                'Classified military (50+ years)'
            ],
            'Lifetime': [1, 2, 10, 10, 30, 70, 50],
            'RSA Safe Until': [
                quantum_optimistic,
                quantum_optimistic,
                quantum_optimistic if 10 + 2024 < quantum_optimistic else 'AT RISK',
                quantum_optimistic if 10 + 2024 < quantum_optimistic else 'AT RISK',
                'AT RISK',
                'AT RISK',
                'AT RISK'
            ]
        }
        
        df_risk = pd.DataFrame(data_types)
        st.dataframe(df_risk, use_container_width=True)
        
        st.error("""
        **Critical Finding:** Most long-lived data is already at risk from 
        "harvest now, decrypt later" attacks. Adversaries are collecting 
        encrypted data TODAY to decrypt when quantum computers arrive.
        """)
        
        # Statistics summary
        stats = self.logger.get_statistics()
        
        if stats['total_attacks'] > 0:
            st.markdown("---")
            st.markdown("### 📊 Your Simulation Statistics")
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Simulations", stats['total_attacks'])
            with col2:
                st.metric("Cryptographic Attacks", 
                         stats['attack_types'].get('Cryptographic', 0))
            with col3:
                st.metric("Protocol Attacks",
                         stats['attack_types'].get('Protocol', 0))
            with col4:
                success_rate = (stats['successful_attacks'] / stats['total_attacks']) * 100
                st.metric("Success Rate", f"{success_rate:.1f}%")
            
            st.info(f"""
            You've explored **{stats['total_attacks']} attack scenarios**. 
            This hands-on learning demonstrates why multi-layered security is essential.
            """)