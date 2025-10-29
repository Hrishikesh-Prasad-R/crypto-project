# 🔒 Post-Quantum Cryptography Demo

A practical learning project showcasing hybrid secure-messaging with post-quantum cryptography (Kyber768 and Dilithium3) combined with AES-256-GCM. Includes attack demonstrations, performance benchmarks, and an interactive Streamlit interface.

## 🎯 Highlights

- **Quantum-Safe Key Exchange**: Kyber768 (NIST Level 3)
- **Quantum-Safe Signatures**: Dilithium3 (NIST Level 3)
- **Hybrid Encryption**: AES-256-GCM for authenticated encryption
- **Interactive Web UI**: Clean, beginner-friendly Streamlit interface
- **Attack Simulations**: MITM, tampering, signature forgery demonstrations
- **Performance Benchmarking**: Cryptographic operation analysis with visualizations
- **Quantum Threat Calculator**: Long-term security planning tool

Perfect for anyone curious about post-quantum cryptography who wants to explore, break, and benchmark crypto protocols hands-on.

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip package manager

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Hrishikesh-Prasad-R/crypto-project.git
cd crypto-project
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Run the Demo

```bash
cd src
streamlit run streamlit_app.py
```

## 📁 Project Structure

```
api_mini_project/
├── .gitignore                    # Keeps repo clean (excludes keys, binaries, cache)
├── packages.txt                  # System dependencies for crypto compilation
├── readme.md                     # This file
├── requirements.txt              # Python dependencies
│
└── src/
    ├── streamlit_app.py          # Main web interface
    │
    ├── attack_simulations/       # Attack modeling and cryptanalysis
    │   ├── attacks.py
    │   ├── attack_analysis.py
    │   ├── attack_brute_force.py
    │   ├── attack_cryptographic.py
    │   ├── attack_logger.py
    │   ├── attack_protocol.py
    │   ├── attack_signature_methods.py
    │   └── attack_visualizer.py
    │
    ├── executables/              # Python wrappers for C implementations
    │   ├── aes_handler.py
    │   ├── dilithium_wrapper.py
    │   └── kyber_wrapper.py
    │   # Note: Binary directories (aes_gcm/, dilithium/, kyber/) excluded via .gitignore
    │
    └── python_files/             # Core cryptographic system logic
        ├── config.py
        ├── crypto_system.py
        ├── diagnostics.py
        ├── key_generation.py
        ├── performance_analysis.py
        ├── quantum_calculator.py
        └── secure_messaging.py
```

## 🔐 Cryptographic Algorithms

### Kyber768 (Key Encapsulation Mechanism)
- **Security Level**: NIST Level 3 (≈ AES-192)
- **Public Key**: 1,184 bytes
- **Ciphertext**: 1,088 bytes
- **Shared Secret**: 32 bytes
- **Purpose**: Quantum-resistant key exchange

### Dilithium3 (Digital Signature Scheme)
- **Security Level**: NIST Level 3
- **Public Key**: 1,952 bytes
- **Secret Key**: 4,032 bytes
- **Signature**: ~3,293 bytes
- **Purpose**: Quantum-resistant authentication and integrity

### AES-256-GCM (Symmetric Encryption)
- **Key Size**: 256 bits
- **Mode**: Galois/Counter Mode (authenticated encryption)
- **Purpose**: Fast, secure message encryption with integrity

**Real security for hypothetical quantum dystopias.**

## 🌐 Web Interface Capabilities

✅ **Key Generation**: Generate quantum-safe keypairs for Alice and Bob  
✅ **Secure Messaging**: End-to-end encrypted communication with signature verification  
✅ **Attack Demonstrations**: MITM interception, message tampering, signature forgery  
✅ **Performance Benchmarks**: Real-time metrics with statistical charts  
✅ **Quantum Threat Assessment**: Timeline predictions and migration planning  

Everything is visual, interactive, and beginner-friendly.

## 🔥 Attack Demonstrations

Attack scripts model real-world cryptographic failures:

- **MITM Attack**: Key exchange interception
- **Message Tampering**: Ciphertext modification detection
- **Signature Forgery**: Authentication bypass attempts
- **Brute Force**: Weak parameter vulnerability testing
- **Protocol Attacks**: System-level security analysis

**Reminder**: Cryptography isn't a magic forcefield. The threat model matters.

## 📊 Performance Benchmarking

- Key generation timing analysis
- Encryption/decryption throughput
- Statistical reports with distribution plots
- Configurable iteration counts
- Speed and stability measurements under repeated operations

## 📚 Educational Takeaways

This project demonstrates:

- **PQC Motivation**: Why quantum computers threaten current cryptography
- **NIST Standardization**: Round 4 selection process
- **Hybrid Encryption Design**: Combining classical and quantum-safe algorithms
- **Signature Verification**: Authentication workflows
- **Authenticated Encryption**: Why MAC/signatures matter
- **Attack Surface Analysis**: How adversaries exploit protocol weaknesses

Works as both a demonstration tool and hands-on learning playground.

## 🛡️ Security Features

- ✅ **Quantum-Resistant**: Protected against Shor's and Grover's algorithms
- ✅ **Forward Secrecy**: Past sessions secure even if keys compromised
- ✅ **Authentication**: Cryptographic proof of sender identity
- ✅ **Integrity**: Tampering detection through digital signatures
- ✅ **Confidentiality**: Military-grade AES-256-GCM encryption

## ⚠️ Security Notice

**This is a research and educational tool.**

- ❌ Not constant-time (vulnerable to timing attacks)
- ❌ Not professionally audited
- ❌ Not production-ready
- ✅ Use established libraries ([liboqs](https://github.com/open-quantum-safe/liboqs), [PQClean](https://github.com/PQClean/PQClean)) for real deployments

## 🤝 Contributing

Contributions welcome! Ideas for enhancement:

- Additional PQC schemes (NTRU, SPHINCS+, FrodoKEM)
- Side-channel attack experiments
- UI/UX improvements
- Enhanced visualizations
- Automated testing suite
- Performance optimizations

Submit a PR or open an issue to collaborate.

## 🔧 Technical Dependencies

- `pycryptodome`: AES-GCM implementation
- `streamlit`: Web interface framework
- `plotly`: Interactive data visualizations
- `colorama`: Terminal color formatting
- `numpy`: Numerical operations

**Platform Support**: Windows, Linux, macOS | Python 3.8+

## 🔗 References

- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CRYSTALS-Kyber Specification](https://pq-crystals.org/kyber/)
- [CRYSTALS-Dilithium Specification](https://pq-crystals.org/dilithium/)
- [PQC Migration Best Practices](https://www.nist.gov/publications/migration-post-quantum-cryptography)

## 👨‍💻 Author

**Hrishikesh R Prasad**

---

**⭐ If you find this project useful, star the repository!**  
**📧 Questions or feedback? Open an issue on GitHub.**