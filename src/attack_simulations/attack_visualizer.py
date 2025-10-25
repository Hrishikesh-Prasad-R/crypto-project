"""
Attack Visualization Tools
Professional charts and graphs for attack demonstrations

FILE: attack_visualizer.py
"""

import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np


class AttackVisualizer:
    """Professional visualization tools for attack demonstrations"""
    
    @staticmethod
    def create_security_comparison(algorithms, security_bits, colors=None):
        """Create security level comparison chart"""
        if colors is None:
            colors = ['red', 'orange', 'yellow', 'lightgreen', 'green', 'darkgreen']
        
        fig = go.Figure()
        
        fig.add_trace(go.Bar(
            x=algorithms,
            y=security_bits,
            marker_color=colors[:len(algorithms)],
            text=[f"2^{b}" for b in security_bits],
            textposition='auto',
            hovertemplate='<b>%{x}</b><br>Security: %{text}<br><extra></extra>'
        ))
        
        fig.add_hline(
            y=128,
            line_dash="dash",
            line_color="red",
            annotation_text="Minimum Security (2^128)",
            annotation_position="right"
        )
        
        fig.update_layout(
            title='Cryptographic Security Levels',
            xaxis_title='Algorithm',
            yaxis_title='Security Bits',
            yaxis_type='log',
            showlegend=False,
            height=450,
            hovermode='x unified'
        )
        
        return fig
    
    @staticmethod
    def create_quantum_vs_classical(algorithms, classical_bits, quantum_bits):
        """Compare classical and quantum security"""
        fig = go.Figure()
        
        fig.add_trace(go.Bar(
            name='Classical Security',
            x=algorithms,
            y=classical_bits,
            marker_color='lightblue',
            text=[f"2^{b}" if b > 0 else "Broken" for b in classical_bits],
            textposition='auto'
        ))
        
        fig.add_trace(go.Bar(
            name='Quantum Security',
            x=algorithms,
            y=quantum_bits,
            marker_color='darkblue',
            text=[f"2^{b}" if b > 0 else "Broken" for b in quantum_bits],
            textposition='auto'
        ))
        
        fig.update_layout(
            title='Classical vs Quantum Security Levels',
            xaxis_title='Algorithm',
            yaxis_title='Security Bits',
            yaxis_type='log',
            barmode='group',
            height=450,
            hovermode='x unified'
        )
        
        return fig
    
    @staticmethod
    def create_attack_timeline(years, rsa_security, pqc_security, quantum_year, data_expiry):
        """Create security timeline visualization"""
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=years,
            y=rsa_security,
            fill='tozeroy',
            name='RSA-2048',
            line=dict(color='red', width=2),
            hovertemplate='Year: %{x}<br>Security: %{y}%<extra></extra>'
        ))
        
        fig.add_trace(go.Scatter(
            x=years,
            y=pqc_security,
            fill='tozeroy',
            name='Kyber768 (PQC)',
            line=dict(color='green', width=2),
            hovertemplate='Year: %{x}<br>Security: %{y}%<extra></extra>'
        ))
        
        fig.add_vline(
            x=quantum_year,
            line_dash="dash",
            annotation_text=f"Quantum Threat ({quantum_year})",
            line_color="red",
            annotation_position="top"
        )
        
        fig.add_vline(
            x=data_expiry,
            line_dash="dash",
            annotation_text=f"Data Expiry ({data_expiry})",
            line_color="blue",
            annotation_position="bottom"
        )
        
        fig.update_layout(
            title='Security Over Time: Classical vs Post-Quantum',
            xaxis_title='Year',
            yaxis_title='Security Level (%)',
            yaxis_range=[0, 110],
            height=450,
            hovermode='x unified'
        )
        
        return fig
    
    @staticmethod
    def create_timing_distribution(timing_data, title="Timing Measurements"):
        """Create timing attack distribution chart"""
        fig = go.Figure()
        
        fig.add_trace(go.Histogram(
            x=timing_data,
            nbinsx=50,
            name='Timing Distribution',
            marker_color='red',
            opacity=0.7
        ))
        
        mean_time = np.mean(timing_data)
        fig.add_vline(
            x=mean_time,
            line_dash="dash",
            annotation_text=f"Mean: {mean_time:.3f}ms",
            line_color="darkred"
        )
        
        fig.update_layout(
            title=title,
            xaxis_title='Execution Time (ms)',
            yaxis_title='Frequency',
            height=400,
            showlegend=False
        )
        
        return fig
    
    @staticmethod
    def create_byte_distribution_comparison(legit_bytes, forged_bytes):
        """Compare byte distributions"""
        fig = make_subplots(
            rows=1, cols=2,
            subplot_titles=("Legitimate Signature", "Forged Signature")
        )
        
        fig.add_trace(
            go.Histogram(
                x=legit_bytes,
                nbinsx=32,
                name="Legitimate",
                marker_color='green',
                showlegend=False
            ),
            row=1, col=1
        )
        
        fig.add_trace(
            go.Histogram(
                x=forged_bytes,
                nbinsx=32,
                name="Forged",
                marker_color='red',
                showlegend=False
            ),
            row=1, col=2
        )
        
        fig.update_layout(
            title_text="Byte Distribution Analysis",
            height=400
        )
        
        fig.update_xaxes(title_text="Byte Value", row=1, col=1)
        fig.update_xaxes(title_text="Byte Value", row=1, col=2)
        fig.update_yaxes(title_text="Frequency", row=1, col=1)
        fig.update_yaxes(title_text="Frequency", row=1, col=2)
        
        return fig
    
    @staticmethod
    def create_defense_layers_chart(protections, blocked):
        """Visualize defense in depth"""
        attacks = list(protections.keys())
        protection_status = [100 if protections[a] else 0 for a in attacks]
        colors = ['green' if p == 100 else 'red' for p in protection_status]
        labels = ['✓ Blocked' if p == 100 else '✗ Vulnerable' for p in protection_status]
        
        fig = go.Figure()
        
        fig.add_trace(go.Bar(
            y=attacks,
            x=protection_status,
            orientation='h',
            marker_color=colors,
            text=labels,
            textposition='inside',
            textfont=dict(color='white', size=14, family='Arial Black'),
            hovertemplate='<b>%{y}</b><br>Status: %{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title=f'Attack Protection Status ({blocked}/{len(attacks)} Blocked)',
            xaxis_title='Protection (%)',
            yaxis_title='Attack Type',
            xaxis_range=[0, 100],
            showlegend=False,
            height=500
        )
        
        return fig
    
    @staticmethod
    def create_attack_success_matrix_heatmap(matrix_data):
        """Create attack success heatmap"""
        # Convert ✓/✗ to 1/0 for heatmap
        attacks = matrix_data['Attack Type']
        systems = [col for col in matrix_data.keys() if col != 'Attack Type']
        
        z_data = []
        for attack_idx in range(len(attacks)):
            row = []
            for system in systems:
                value = matrix_data[system][attack_idx]
                row.append(1 if value == '✓' else 0)
            z_data.append(row)
        
        fig = go.Figure(data=go.Heatmap(
            z=z_data,
            x=systems,
            y=attacks,
            colorscale=[[0, 'green'], [1, 'red']],
            showscale=False,
            text=[[matrix_data[sys][i] for sys in systems] for i in range(len(attacks))],
            texttemplate='<b>%{text}</b>',
            textfont={"size": 18, "color": "white"},
            hovertemplate='<b>%{y}</b><br>System: %{x}<br>Status: %{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title='Attack Success Matrix (✓ = Attack Succeeds, ✗ = Blocked)',
            xaxis_title='Security System',
            yaxis_title='Attack Type',
            height=600
        )
        
        return fig
    
    @staticmethod
    def create_radar_chart(categories, pqc_scores, classical_scores):
        """Create radar chart for comparison"""
        fig = go.Figure()
        
        fig.add_trace(go.Scatterpolar(
            r=pqc_scores,
            theta=categories,
            fill='toself',
            name='Post-Quantum (Kyber768)',
            line_color='green',
            fillcolor='rgba(0, 255, 0, 0.2)'
        ))
        
        fig.add_trace(go.Scatterpolar(
            r=classical_scores,
            theta=categories,
            fill='toself',
            name='Classical (RSA-2048)',
            line_color='red',
            fillcolor='rgba(255, 0, 0, 0.2)'
        ))
        
        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 100]
                )
            ),
            showlegend=True,
            title="Security Comparison: PQC vs Classical",
            height=500
        )
        
        return fig