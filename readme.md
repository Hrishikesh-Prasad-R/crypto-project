# 🔒 Post-Quantum Cryptography Demo

A comprehensive Python implementation demonstrating post-quantum cryptographic algorithms (Kyber768 and Dilithium3) with interactive visualizations and security demonstrations.

## 🌟 Features

- **Post-Quantum Key Exchange**: Kyber768 for quantum-resistant key encapsulation
- **Digital Signatures**: Dilithium3 for quantum-safe authentication
- **Hybrid Encryption**: AES-256-GCM combined with post-quantum key exchange
- **Interactive Web Interface**: Streamlit-based UI for easy demonstration
- **Security Demonstrations**: Attack simulations (MITM, tampering, forgery)
- **Performance Analysis**: Real-time benchmarking and visualization
- **Quantum Threat Calculator**: Assess cryptographic algorithm vulnerabilities

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

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Running the Application

#### Web Interface (Recommended)
```bash
cd src
streamlit run web_interface.py
```

#### Command Line Demos
```bash
cd src
python main.py              # Main interactive menu
python demo.py              # Basic demo
python protocol_demo.py     # Full protocol demonstration
python attack_demo.py       # Security attack simulations
python performance_graphs.py # Performance benchmarks
```

## 📁 Project Structure

```
crypto-project/
├── src/
│   ├── aes_gcm/              # AES-256-GCM implementation
│   ├── dilithium/            # Dilithium3 signature scheme
│   ├── kyber/                # Kyber768 KEM implementation
│   ├── aes_handler.py        # AES encryption wrapper
│   ├── crypto_system.py      # Main cryptographic system
│   ├── dilithium_wrapper.py  # Dilithium integration
│   ├── kyber_wrapper.py      # Kyber integration
│   ├── main.py               # CLI menu interface
│   ├── demo.py               # Basic demonstration
│   ├── protocol_demo.py      # Full protocol demo
│   ├── attack_demo.py        # Attack simulations
│   ├── performance_graphs.py # Performance benchmarking
│   ├── quantum_calculator.py # Quantum threat analysis
│   └── web_interface.py      # Streamlit web UI
├── requirements.txt          # Python dependencies
├── .gitignore               # Git ignore rules
└── README.md                # This file
```

## 🔐 Cryptographic Algorithms

### Kyber768 (Key Encapsulation Mechanism)
- **Security Level**: NIST Level 3 (equivalent to AES-192)
- **Public Key**: 1,184 bytes
- **Ciphertext**: 1,088 bytes
- **Shared Secret**: 32 bytes
- **Purpose**: Quantum-resistant key exchange

### Dilithium3 (Digital Signature)
- **Security Level**: NIST Level 3
- **Public Key**: 1,952 bytes
- **Secret Key**: 4,032 bytes
- **Signature**: ~3,293 bytes
- **Purpose**: Quantum-resistant authentication

### AES-256-GCM (Symmetric Encryption)
- **Key Size**: 256 bits
- **Mode**: Galois/Counter Mode (authenticated encryption)
- **Purpose**: Fast, secure message encryption

## 🎯 Use Cases Demonstrated

### 1. Secure Messaging
- End-to-end encrypted communication
- Digital signature verification
- Forward secrecy through ephemeral keys

### 2. Attack Resistance
- Man-in-the-Middle (MITM) attack detection
- Message tampering prevention
- Signature forgery protection

### 3. Performance Benchmarking
- Key generation speed
- Encryption/decryption throughput
- Statistical analysis with visualizations

### 4. Quantum Threat Assessment
- Timeline predictions for quantum computer threats
- Algorithm vulnerability analysis
- Migration planning recommendations


## 🛡️ Security Features

- ✅ **Quantum-Resistant**: Protected against Shor's algorithm
- ✅ **Forward Secrecy**: Past sessions remain secure if keys compromised
- ✅ **Authentication**: Cryptographic proof of sender identity
- ✅ **Integrity**: Tampering detection through signatures
- ✅ **Confidentiality**: AES-256-GCM encryption

## 🎨 Web Interface Features

### Key Generation
- Generate quantum-safe keypairs for Alice and Bob
- Visualize key sizes
- View public keys in hexadecimal

### Secure Messaging
- Encrypt messages with post-quantum algorithms
- Decrypt and verify signatures
- Real-time performance metrics

### Attack Simulations
- Man-in-the-Middle attacks
- Message tampering detection
- Signature forgery attempts

### Performance Analysis
- Configurable benchmark iterations
- Statistical distribution plots
- Average and standard deviation metrics

### Quantum Calculator
- Assess cryptographic algorithm lifetimes
- Visualize quantum threat timelines
- Get migration recommendations

## 📚 Educational Resources

This project demonstrates:
- Post-quantum cryptography basics
- NIST standardization process
- Hybrid encryption schemes
- Digital signature protocols
- Key encapsulation mechanisms
- Attack surface analysis

## 🔧 Technical Details

### Dependencies
- `pycryptodome`: AES-GCM implementation
- `streamlit`: Web interface
- `plotly`: Interactive visualizations
- `colorama`: Terminal colors
- `numpy`: Numerical operations

### Compatibility
- Cross-platform (Windows, Linux, macOS)
- Python 3.8+
- No external cryptographic libraries required for PQC

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Additional post-quantum algorithms (NTRU, SPHINCS+)
- More attack simulations
- Performance optimizations
- Additional visualizations
- Documentation improvements

## 📝 License

This project is for educational purposes. See LICENSE file for details.

## ⚠️ Security Notice

**This is a demonstration project for educational purposes.**

- Do NOT use in production systems without thorough security audit
- Implementations may not be constant-time (vulnerable to timing attacks)
- Not optimized for production use
- Use established libraries (liboqs, PQClean) for real applications

## 🔗 References

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Kyber Specification](https://pq-crystals.org/kyber/)
- [Dilithium Specification](https://pq-crystals.org/dilithium/)
- [PQC Migration Best Practices](https://www.nist.gov/publications/migration-post-quantum-cryptography)

## 👨‍💻 Author

Hrishikesh R Prasad

## 🙏 Acknowledgments

- NIST for post-quantum cryptography standardization
- CRYSTALS team for Kyber and Dilithium algorithms
- Open-source cryptography community

---

**⭐ If you find this project useful, please star the repository!**

**📧 For questions or feedback, open an issue on GitHub.**