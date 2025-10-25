"""
Quantum Threat Calculator
Analyzes and predicts when various algorithms will be broken
"""

import math
from datetime import datetime
from colorama import init, Fore, Style
init(autoreset=True)

class QuantumThreatCalculator:
    def __init__(self):
        self.current_year = datetime.now().year
        
        # Algorithm security parameters
        self.algorithms = {
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
        self.qc_milestones = {
            2024: {'qubits': 1000, 'error_rate': 0.001, 'capability': 'Limited'},
            2027: {'qubits': 5000, 'error_rate': 0.0001, 'capability': 'Breaking RSA-1024 possible'},
            2030: {'qubits': 20000, 'error_rate': 0.00001, 'capability': 'Breaking RSA-2048 feasible'},
            2035: {'qubits': 100000, 'error_rate': 0.000001, 'capability': 'Breaking RSA-4096 possible'},
            2040: {'qubits': 1000000, 'error_rate': 0.0000001, 'capability': 'Full-scale quantum attacks'},
        }
    
    def print_header(self, text):
        print("\n" + "="*80)
        print(f"{Fore.CYAN}{text}")
        print("="*80)
    
    def calculate_classical_attack_time(self, security_bits):
        """Calculate time to break with classical computer"""
        operations = 2 ** security_bits
        ops_per_second = 1e12  # 1 trillion ops/sec (optimistic)
        seconds = operations / ops_per_second
        years = seconds / (365.25 * 24 * 3600)
        return years
    
    def calculate_quantum_attack_time(self, security_bits, year=2030):
        """Estimate time to break with quantum computer"""
        if security_bits == 0:
            return 0.001  # Essentially instant (Shor's algorithm)
        
        # Grover's algorithm reduces security by half
        quantum_bits = security_bits // 2
        operations = 2 ** quantum_bits
        
        # Quantum operations are much slower
        if year in self.qc_milestones:
            # Very rough estimate
            ops_per_second = self.qc_milestones[year]['qubits'] * 1000
        else:
            ops_per_second = 1e6  # Conservative estimate
        
        seconds = operations / ops_per_second
        years = seconds / (365.25 * 24 * 3600)
        return years
    
    def estimate_break_year(self, algorithm_name):
        """Estimate when an algorithm will be practically breakable"""
        algo = self.algorithms[algorithm_name]
        
        if algo['quantum_bits'] == 0:
            # Vulnerable to Shor's algorithm
            # Estimate based on qubit requirements
            if 'RSA-1024' in algorithm_name:
                return 2027
            elif 'RSA-2048' in algorithm_name:
                return 2030
            elif 'RSA-3072' in algorithm_name:
                return 2033
            elif 'RSA-4096' in algorithm_name:
                return 2035
            elif 'ECC' in algorithm_name:
                return 2028
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
    
    def analyze_algorithm(self, algorithm_name):
        """Comprehensive analysis of an algorithm"""
        algo = self.algorithms[algorithm_name]
        
        print(f"\n{Fore.YELLOW}{'─'*80}")
        print(f"{Fore.CYAN}ALGORITHM: {algorithm_name}")
        print(f"{Fore.YELLOW}{'─'*80}")
        
        print(f"\n📊 Security Parameters:")
        print(f"   Key Size: {algo['key_size']} bits")
        print(f"   Classical Security: {algo['classical_bits']} bits")
        print(f"   Quantum Security: {algo['quantum_bits']} bits")
        
        # Classical attack analysis
        classical_years = self.calculate_classical_attack_time(algo['classical_bits'])
        print(f"\n🖥️  Classical Computer Attack:")
        if classical_years > 1e10:
            print(f"   Time to break: {Fore.GREEN}Longer than age of universe")
            print(f"   Status: {Fore.GREEN}SECURE ✓")
        else:
            print(f"   Time to break: {classical_years:.2e} years")
            if classical_years > 1000:
                print(f"   Status: {Fore.GREEN}SECURE ✓")
            else:
                print(f"   Status: {Fore.RED}VULNERABLE ✗")
        
        # Quantum attack analysis
        print(f"\n⚛️  Quantum Computer Attack:")
        if algo['quantum_bits'] == 0:
            print(f"   {Fore.RED}BROKEN by Shor's Algorithm")
            print(f"   Time to break: Minutes to hours (with sufficient qubits)")
            break_year = self.estimate_break_year(algorithm_name)
            print(f"   Estimated break year: {Fore.RED}{break_year}")
            
            years_until = break_year - self.current_year
            if years_until <= 0:
                print(f"   {Fore.RED}⚠️  ALREADY VULNERABLE!")
            elif years_until <= 5:
                print(f"   {Fore.RED}⚠️  MIGRATE IMMEDIATELY! ({years_until} years)")
            elif years_until <= 10:
                print(f"   {Fore.YELLOW}⚠️  MIGRATION URGENT! ({years_until} years)")
            else:
                print(f"   {Fore.YELLOW}Migration recommended within {years_until} years")
        else:
            quantum_years = self.calculate_quantum_attack_time(algo['quantum_bits'])
            print(f"   Time to break: {quantum_years:.2e} years")
            
            if quantum_years > 1e6:
                print(f"   Status: {Fore.GREEN}QUANTUM-SAFE ✓")
            elif quantum_years > 1000:
                print(f"   Status: {Fore.YELLOW}Moderately secure")
            else:
                print(f"   Status: {Fore.RED}Potentially vulnerable")
        
        # Recommendation
        print(f"\n💡 Recommendation:")
        if algo['quantum_bits'] == 0:
            print(f"   {Fore.RED}⚠️  NOT RECOMMENDED for long-term security")
            print(f"   {Fore.RED}⚠️  Vulnerable to quantum computers")
            print(f"   {Fore.CYAN}→  Migrate to post-quantum alternatives")
        elif algo['quantum_bits'] >= 96:
            print(f"   {Fore.GREEN}✓ EXCELLENT for long-term security")
            print(f"   {Fore.GREEN}✓ Quantum-resistant")
        elif algo['quantum_bits'] >= 64:
            print(f"   {Fore.YELLOW}⚠️  ADEQUATE for medium-term security")
            print(f"   {Fore.CYAN}→  Consider higher security levels for critical data")
        else:
            print(f"   {Fore.RED}⚠️  NOT RECOMMENDED")
    
    def compare_algorithms(self):
        """Compare multiple algorithms"""
        self.print_header("ALGORITHM COMPARISON TABLE")
        
        print(f"\n{Fore.CYAN}Classical Security Ranking:")
        classical_sorted = sorted(self.algorithms.items(), 
                                 key=lambda x: x[1]['classical_bits'], 
                                 reverse=True)
        
        print(f"\n{'Algorithm':<20} {'Classical':<12} {'Quantum':<12} {'Status':<15}")
        print("─"*80)
        
        for name, algo in classical_sorted:
            classical = f"{algo['classical_bits']} bits"
            quantum = f"{algo['quantum_bits']} bits" if algo['quantum_bits'] > 0 else "BROKEN"
            
            if algo['quantum_bits'] == 0:
                status = f"{Fore.RED}Vulnerable"
            elif algo['quantum_bits'] >= 96:
                status = f"{Fore.GREEN}Quantum-Safe"
            else:
                status = f"{Fore.YELLOW}Moderate"
            
            print(f"{name:<20} {classical:<12} {quantum:<12} {status}")
    
    def quantum_timeline(self):
        """Show quantum computer development timeline"""
        self.print_header("QUANTUM COMPUTER DEVELOPMENT TIMELINE")
        
        for year, data in sorted(self.qc_milestones.items()):
            if year >= self.current_year:
                years_away = year - self.current_year
                print(f"\n{Fore.CYAN}{year} ({years_away} years from now):")
            else:
                print(f"\n{Fore.CYAN}{year} (Past):")
            
            print(f"   Qubits: ~{data['qubits']:,}")
            print(f"   Error Rate: {data['error_rate']}")
            print(f"   Capability: {data['capability']}")
    
    def interactive_calculator(self):
        """Interactive threat calculator"""
        self.print_header("INTERACTIVE QUANTUM THREAT CALCULATOR")
        
        print("\nAvailable algorithms:")
        for i, name in enumerate(self.algorithms.keys(), 1):
            print(f"   {i}. {name}")
        
        print(f"\n{Fore.YELLOW}Enter algorithm numbers to analyze (comma-separated), or 'all':")
        choice = input("> ").strip()
        
        if choice.lower() == 'all':
            for name in self.algorithms.keys():
                self.analyze_algorithm(name)
                input(f"\n{Fore.YELLOW}Press Enter to continue...")
        else:
            try:
                indices = [int(x.strip()) for x in choice.split(',')]
                algo_names = list(self.algorithms.keys())
                for idx in indices:
                    if 1 <= idx <= len(algo_names):
                        self.analyze_algorithm(algo_names[idx-1])
                        if idx != indices[-1]:
                            input(f"\n{Fore.YELLOW}Press Enter to continue...")
            except:
                print(f"{Fore.RED}Invalid input!")
    
    def harvest_attack_analysis(self):
        """Analyze 'Harvest Now, Decrypt Later' threat"""
        self.print_header("'HARVEST NOW, DECRYPT LATER' THREAT ANALYSIS")
        
        print(f"\n{Fore.YELLOW}Threat Scenario:")
        print("   1. Attacker captures encrypted data TODAY (2024)")
        print("   2. Attacker stores the encrypted data")
        print("   3. Attacker waits for quantum computers to be available")
        print("   4. Attacker decrypts historical data with quantum computer")
        
        print(f"\n{Fore.RED}⚠️  Critical Insight:")
        print("   If your data needs to stay secret for 10+ years,")
        print("   you MUST use post-quantum cryptography NOW!")
        
        data_lifetimes = [5, 10, 15, 20, 25, 30]
        
        print(f"\n{Fore.CYAN}Data Protection Timeline:")
        print(f"\n{'Data Lifetime':<20} {'RSA-2048':<20} {'Kyber768':<20}")
        print("─"*80)
        
        for lifetime in data_lifetimes:
            target_year = self.current_year + lifetime
            
            if target_year >= 2030:
                rsa_status = f"{Fore.RED}AT RISK ✗"
            else:
                rsa_status = f"{Fore.YELLOW}Probably OK"
            
            kyber_status = f"{Fore.GREEN}SECURE ✓"
            
            print(f"{lifetime} years ({target_year}){'':<3} {rsa_status:<30} {kyber_status}")
        
        print(f"\n{Fore.RED}💡 Recommendation:")
        print(f"   • Medical records (70+ year lifetime): {Fore.RED}Use PQC NOW")
        print(f"   • Government secrets (50+ years): {Fore.RED}Use PQC NOW")
        print(f"   • Financial data (10+ years): {Fore.YELLOW}Migrate to PQC soon")
        print(f"   • Personal messages (<5 years): {Fore.YELLOW}Consider PQC")

def main():
    calc = QuantumThreatCalculator()
    
    print(f"{Fore.CYAN}" + "="*80)
    print(f"{Fore.CYAN}QUANTUM THREAT CALCULATOR")
    print(f"{Fore.CYAN}Analyzing Cryptographic Algorithm Security")
    print(f"{Fore.CYAN}" + "="*80)
    
    # Show timeline
    calc.quantum_timeline()
    input(f"\n{Fore.YELLOW}Press Enter to continue...")
    
    # Show comparison
    calc.compare_algorithms()
    input(f"\n{Fore.YELLOW}Press Enter to continue...")
    
    # Harvest attack
    calc.harvest_attack_analysis()
    input(f"\n{Fore.YELLOW}Press Enter to continue...")
    
    # Interactive analysis
    calc.interactive_calculator()
    
    print(f"\n{Fore.GREEN}" + "="*80)
    print(f"{Fore.GREEN}ANALYSIS COMPLETE")
    print(f"{Fore.GREEN}" + "="*80)

if __name__ == "__main__":
    main()