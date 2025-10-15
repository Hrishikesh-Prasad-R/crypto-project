"""
Performance Visualization Module
Creates beautiful graphs comparing PQC vs Classical crypto
"""

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import time
from crypto_system import SecureChannel
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pandas as pd

# Set style
sns.set_style("whitegrid")
sns.set_palette("husl")
plt.rcParams['figure.figsize'] = (12, 8)

class PerformanceBenchmark:
    def __init__(self):
        self.channel = SecureChannel()
        self.results = {}
    
    def benchmark_pqc(self, iterations=10):
        """Benchmark post-quantum crypto"""
        print(f"Benchmarking Kyber768 + Dilithium3 ({iterations} iterations)...")
        
        keygen_times = []
        encrypt_times = []
        decrypt_times = []
        sign_times = []
        verify_times = []
        
        for i in range(iterations):
            # Key generation
            start = time.time()
            keys = self.channel.generate_keys()
            keygen_times.append((time.time() - start) * 1000)
            
            # Encryption
            message = "Test message for benchmarking" * 10
            start = time.time()
            package = self.channel.send_message(
                message,
                keys['kem_public'],
                keys['sign_secret']
            )
            encrypt_times.append((time.time() - start) * 1000)
            
            # Decryption
            start = time.time()
            decrypted = self.channel.receive_message(
                package,
                keys['kem_secret'],
                keys['sign_public']
            )
            decrypt_times.append((time.time() - start) * 1000)
            
            print(f"  Iteration {i+1}/{iterations} complete")
        
        return {
            'keygen': keygen_times,
            'encrypt': encrypt_times,
            'decrypt': decrypt_times
        }
    
    def benchmark_rsa(self, iterations=10):
        """Benchmark RSA for comparison"""
        print(f"Benchmarking RSA-2048 ({iterations} iterations)...")
        
        keygen_times = []
        encrypt_times = []
        decrypt_times = []
        
        for i in range(iterations):
            # Key generation
            start = time.time()
            key = RSA.generate(2048)
            keygen_times.append((time.time() - start) * 1000)
            
            cipher = PKCS1_OAEP.new(key.publickey())
            
            # Encryption (RSA can only encrypt small messages)
            message = b"Test message for benchmarking"
            start = time.time()
            ciphertext = cipher.encrypt(message)
            encrypt_times.append((time.time() - start) * 1000)
            
            # Decryption
            decipher = PKCS1_OAEP.new(key)
            start = time.time()
            plaintext = decipher.decrypt(ciphertext)
            decrypt_times.append((time.time() - start) * 1000)
            
            print(f"  Iteration {i+1}/{iterations} complete")
        
        return {
            'keygen': keygen_times,
            'encrypt': encrypt_times,
            'decrypt': decrypt_times
        }
    
    def plot_timing_comparison(self, pqc_data, rsa_data):
        """Create timing comparison charts"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Performance Comparison: Post-Quantum vs Classical Cryptography', 
                     fontsize=16, fontweight='bold')
        
        operations = ['keygen', 'encrypt', 'decrypt']
        titles = ['Key Generation', 'Encryption', 'Decryption']
        
        # Individual operation comparisons
        for idx, (op, title) in enumerate(zip(operations, titles)):
            if idx < 3:
                ax = axes[idx // 2, idx % 2]
                
                data_to_plot = [pqc_data[op], rsa_data[op]]
                bp = ax.boxplot(data_to_plot, labels=['Kyber768/Dilithium3', 'RSA-2048'],
                               patch_artist=True, showmeans=True)
                
                colors = ['#3498db', '#e74c3c']
                for patch, color in zip(bp['boxes'], colors):
                    patch.set_facecolor(color)
                    patch.set_alpha(0.7)
                
                ax.set_ylabel('Time (milliseconds)', fontweight='bold')
                ax.set_title(f'{title} Time Comparison', fontweight='bold')
                ax.grid(True, alpha=0.3)
                
                # Add mean values as text
                for i, data in enumerate(data_to_plot):
                    mean_val = np.mean(data)
                    ax.text(i+1, max(ax.get_ylim())*0.95, f'μ={mean_val:.2f}ms',
                           ha='center', fontweight='bold')
        
        # Overall comparison bar chart
        ax = axes[1, 1]
        operations_labels = ['KeyGen', 'Encrypt', 'Decrypt']
        pqc_means = [np.mean(pqc_data[op]) for op in operations]
        rsa_means = [np.mean(rsa_data[op]) for op in operations]
        
        x = np.arange(len(operations_labels))
        width = 0.35
        
        bars1 = ax.bar(x - width/2, pqc_means, width, label='Kyber768/Dilithium3',
                      color='#3498db', alpha=0.8)
        bars2 = ax.bar(x + width/2, rsa_means, width, label='RSA-2048',
                      color='#e74c3c', alpha=0.8)
        
        ax.set_ylabel('Time (milliseconds)', fontweight='bold')
        ax.set_title('Average Operation Times', fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(operations_labels)
        ax.legend()
        ax.grid(True, alpha=0.3, axis='y')
        
        # Add value labels on bars
        for bars in [bars1, bars2]:
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{height:.1f}',
                       ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig('performance_comparison.png', dpi=300, bbox_inches='tight')
        print("✓ Saved: performance_comparison.png")
        plt.show()
    
    def plot_security_levels(self):
        """Visualize security levels"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        fig.suptitle('Security Analysis: Classical vs Quantum Threats', 
                     fontsize=16, fontweight='bold')
        
        # Classical security
        algorithms = ['RSA-2048', 'Kyber512', 'Kyber768', 'Kyber1024']
        classical_bits = [112, 128, 192, 256]
        colors_classical = ['#e74c3c', '#f39c12', '#3498db', '#2ecc71']
        
        bars = ax1.barh(algorithms, classical_bits, color=colors_classical, alpha=0.8)
        ax1.set_xlabel('Security Bits (Classical Attack)', fontweight='bold')
        ax1.set_title('Classical Computer Security', fontweight='bold')
        ax1.grid(True, alpha=0.3, axis='x')
        
        # Add reference lines
        ax1.axvline(x=128, color='orange', linestyle='--', alpha=0.7, label='AES-128 equivalent')
        ax1.axvline(x=256, color='green', linestyle='--', alpha=0.7, label='AES-256 equivalent')
        ax1.legend()
        
        for i, (bar, bits) in enumerate(zip(bars, classical_bits)):
            ax1.text(bits + 5, bar.get_y() + bar.get_height()/2,
                    f'{bits} bits', va='center', fontweight='bold')
        
        # Quantum security
        quantum_bits = [0, 64, 96, 128]  # RSA broken, Kyber halved
        colors_quantum = ['#c0392b', '#f39c12', '#3498db', '#27ae60']
        
        bars = ax2.barh(algorithms, quantum_bits, color=colors_quantum, alpha=0.8)
        ax2.set_xlabel('Security Bits (Quantum Attack)', fontweight='bold')
        ax2.set_title('Quantum Computer Security', fontweight='bold')
        ax2.grid(True, alpha=0.3, axis='x')
        
        # Add danger zone
        ax2.axvspan(0, 80, alpha=0.2, color='red', label='Vulnerable')
        ax2.axvspan(80, 300, alpha=0.2, color='green', label='Secure')
        ax2.legend()
        
        for i, (bar, bits) in enumerate(zip(bars, quantum_bits)):
            if bits == 0:
                ax2.text(5, bar.get_y() + bar.get_height()/2,
                        'BROKEN', va='center', fontweight='bold', color='darkred')
            else:
                ax2.text(bits + 3, bar.get_y() + bar.get_height()/2,
                        f'{bits} bits', va='center', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig('security_levels.png', dpi=300, bbox_inches='tight')
        print("✓ Saved: security_levels.png")
        plt.show()
    
    def plot_key_sizes(self):
        """Compare key and ciphertext sizes"""
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Data
        categories = ['Public Key', 'Secret Key', 'Ciphertext/Signature']
        rsa_sizes = [294, 1192, 256]  # RSA-2048 in bytes
        kyber_sizes = [1184, 2400, 1088]  # Kyber768
        dilithium_sizes = [1952, 4032, 3309]  # Dilithium3
        
        x = np.arange(len(categories))
        width = 0.25
        
        bars1 = ax.bar(x - width, rsa_sizes, width, label='RSA-2048', 
                      color='#e74c3c', alpha=0.8)
        bars2 = ax.bar(x, kyber_sizes, width, label='Kyber768',
                      color='#3498db', alpha=0.8)
        bars3 = ax.bar(x + width, dilithium_sizes, width, label='Dilithium3',
                      color='#2ecc71', alpha=0.8)
        
        ax.set_ylabel('Size (bytes)', fontweight='bold')
        ax.set_title('Cryptographic Primitive Size Comparison', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(categories)
        ax.legend()
        ax.grid(True, alpha=0.3, axis='y')
        
        # Add value labels
        for bars in [bars1, bars2, bars3]:
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}',
                       ha='center', va='bottom', fontweight='bold', fontsize=9)
        
        plt.tight_layout()
        plt.savefig('size_comparison.png', dpi=300, bbox_inches='tight')
        print("✓ Saved: size_comparison.png")
        plt.show()
    
    def plot_attack_timeline(self):
        """Show quantum threat timeline"""
        fig, ax = plt.subplots(figsize=(14, 8))
        
        # Timeline data
        years = np.array([2020, 2025, 2030, 2035, 2040])
        
        # Different scenarios
        optimistic = [0, 10, 30, 60, 90]  # % chance quantum computer breaks RSA
        realistic = [0, 5, 15, 40, 70]
        pessimistic = [0, 2, 8, 20, 50]
        
        ax.plot(years, optimistic, 'r-o', linewidth=2, markersize=8, 
               label='Optimistic (Fast QC Development)', alpha=0.7)
        ax.plot(years, realistic, 'orange', linewidth=2, markersize=8,
               label='Realistic (Moderate Progress)', alpha=0.7)
        ax.plot(years, pessimistic, 'g-o', linewidth=2, markersize=8,
               label='Pessimistic (Slow Progress)', alpha=0.7)
        
        # Add danger zones
        ax.axhspan(50, 100, alpha=0.2, color='red', label='High Risk Zone')
        ax.axhspan(20, 50, alpha=0.2, color='orange')
        ax.axhspan(0, 20, alpha=0.2, color='green', label='Low Risk Zone')
        
        ax.set_xlabel('Year', fontweight='bold', fontsize=12)
        ax.set_ylabel('Probability of Breaking RSA-2048 (%)', fontweight='bold', fontsize=12)
        ax.set_title('Quantum Computer Threat Timeline for RSA-2048', 
                    fontsize=14, fontweight='bold')
        ax.legend(loc='upper left')
        ax.grid(True, alpha=0.3)
        ax.set_ylim(0, 100)
        
        # Add annotations
        ax.annotate('Migrate to PQC NOW!', 
                   xy=(2030, 40), xytext=(2027, 70),
                   arrowprops=dict(arrowstyle='->', color='red', lw=2),
                   fontsize=12, fontweight='bold', color='red')
        
        ax.annotate('NIST PQC Standards Released', 
                   xy=(2024, 5), xytext=(2022, 25),
                   arrowprops=dict(arrowstyle='->', color='blue', lw=2),
                   fontsize=10, fontweight='bold', color='blue')
        
        plt.tight_layout()
        plt.savefig('quantum_threat_timeline.png', dpi=300, bbox_inches='tight')
        print("✓ Saved: quantum_threat_timeline.png")
        plt.show()
    
    def plot_throughput_analysis(self):
        """Analyze encryption throughput vs message size"""
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Simulate different message sizes
        message_sizes_kb = [1, 10, 50, 100, 500, 1000, 5000]
        
        print("Benchmarking throughput for different message sizes...")
        pqc_times = []
        
        keys = self.channel.generate_keys()
        
        for size_kb in message_sizes_kb:
            message = "X" * (size_kb * 1024)  # Create message of size KB
            
            times = []
            for _ in range(5):  # 5 iterations per size
                start = time.time()
                package = self.channel.send_message(
                    message,
                    keys['kem_public'],
                    keys['sign_secret']
                )
                elapsed = time.time() - start
                times.append(elapsed)
            
            avg_time = np.mean(times)
            pqc_times.append(avg_time)
            throughput = size_kb / avg_time  # KB/s
            print(f"  {size_kb}KB: {avg_time:.3f}s ({throughput:.2f} KB/s)")
        
        # Calculate throughput
        throughput_pqc = [size / time for size, time in zip(message_sizes_kb, pqc_times)]
        
        # Plot
        ax.plot(message_sizes_kb, throughput_pqc, 'b-o', linewidth=2, 
               markersize=8, label='Kyber768 + AES-GCM')
        
        ax.set_xlabel('Message Size (KB)', fontweight='bold', fontsize=12)
        ax.set_ylabel('Throughput (KB/second)', fontweight='bold', fontsize=12)
        ax.set_title('Encryption Throughput vs Message Size', fontsize=14, fontweight='bold')
        ax.set_xscale('log')
        ax.legend()
        ax.grid(True, alpha=0.3, which='both')
        
        # Add average throughput line
        avg_throughput = np.mean(throughput_pqc)
        ax.axhline(y=avg_throughput, color='r', linestyle='--', alpha=0.7,
                  label=f'Average: {avg_throughput:.2f} KB/s')
        ax.legend()
        
        plt.tight_layout()
        plt.savefig('throughput_analysis.png', dpi=300, bbox_inches='tight')
        print("✓ Saved: throughput_analysis.png")
        plt.show()

def main():
    print("="*80)
    print("PERFORMANCE BENCHMARKING AND VISUALIZATION")
    print("="*80)
    
    bench = PerformanceBenchmark()
    
    # Run benchmarks
    print("\n[1/2] Running Post-Quantum Crypto Benchmarks...")
    pqc_data = bench.benchmark_pqc(iterations=10)
    
    print("\n[2/2] Running RSA Benchmarks...")
    rsa_data = bench.benchmark_rsa(iterations=10)
    
    print("\n" + "="*80)
    print("GENERATING VISUALIZATIONS")
    print("="*80)
    
    # Generate all graphs
    print("\n[1/6] Creating timing comparison charts...")
    bench.plot_timing_comparison(pqc_data, rsa_data)
    
    print("\n[2/6] Creating security level analysis...")
    bench.plot_security_levels()
    
    print("\n[3/6] Creating size comparison charts...")
    bench.plot_key_sizes()
    
    print("\n[4/6] Creating quantum threat timeline...")
    bench.plot_attack_timeline()
    
    print("\n[5/6] Creating throughput analysis...")
    bench.plot_throughput_analysis()
    
    print("\n" + "="*80)
    print("ALL VISUALIZATIONS COMPLETE!")
    print("="*80)
    print("\nGenerated files:")
    print("  • performance_comparison.png")
    print("  • security_levels.png")
    print("  • size_comparison.png")
    print("  • quantum_threat_timeline.png")
    print("  • throughput_analysis.png")

if __name__ == "__main__":
    main()