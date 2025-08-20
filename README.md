# 🛡️ SolidityGuard - Smart Contract Security Analysis

[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/darksoftinc/intelligent-contract-security)
[![Security](https://img.shields.io/badge/Security-Audit%20Ready-yellow.svg)](https://github.com/darksoftinc/intelligent-contract-security)

> **SolidityGuard** is an advanced security analysis tool that automatically detects vulnerabilities in Solidity smart contracts. It provides professional security auditing with a Rust-powered backend and modern web interface.

## 🚀 Features

### 🔍 **Advanced Vulnerability Detection**
- **Reentrancy Attacks** - Critical level security vulnerability
- **Integer Overflow/Underflow** - Numerical overflow detection
- **Access Control** - Missing permission controls
- **Unchecked External Calls** - Uncontrolled external calls
- **Gas Optimization** - Gas optimization issues
- **Timestamp Dependence** - Timestamp dependencies
- **Weak Randomness** - Weak randomness sources
- **Storage vs Memory** - Storage memory confusion
- **Constructor Issues** - Constructor function problems
- **Fallback Function** - Fallback function security vulnerabilities

### 🎯 **Intelligent Analysis System**
- **Real-time Scanning** - Instant results
- **Security Scoring** - Automatic 0-100 calculation
- **Risk Level Assessment** - Critical, High, Medium, Low
- **Detailed Reporting** - Comprehensive output in JSON format
- **CWE Integration** - Standard vulnerability categories

### 🌐 **Modern Web Interface**
- **Responsive Design** - Mobile and desktop compatible
- **Tailwind CSS** - Modern and elegant appearance
- **Drag & Drop** - Easy file upload
- **Real-time Statistics** - Analysis metrics
- **Visual Security Score** - Circular progress bar
- **Vulnerability Badges** - Color-coded by severity

## 📋 Requirements

- **Rust** 1.75+ ([Rust Installation](https://rustup.rs/))
- **Cargo** (comes with Rust)
- **Modern Web Browser** (Chrome, Firefox, Safari, Edge)

## 🛠️ Installation

### 1. Clone the Project
```bash
git clone https://github.com/darksoftinc/intelligent-contract-security.git
cd intelligent-contract-security
```

### 2. Install Dependencies
```bash
cargo build
```

### 3. Run the Application
```bash
cargo run
```

### 4. Open Web Interface
Open `http://127.0.0.1:3000` in your browser.

## 🎮 Usage

### **Web Interface Analysis**
1. **File Upload**: Drag and drop `.sol` Solidity files
2. **Code Pasting**: Paste code directly
3. **Start Analysis**: Click "Analyze" button
4. **Review Results**: Get detailed report in JSON format

### **Command Line Analysis**
```bash
# Single file analysis
cargo run -- path/to/contract.sol

# Multiple file analysis
for file in contracts/*.sol; do
    cargo run -- "$file"
done
```

### **API Usage**
```bash
# POST request for analysis
curl -X POST http://127.0.0.1:3000/analyze \
  -H "Content-Type: text/plain" \
  --data-binary @contract.sol
```

## 📊 Sample Output

```json
{
  "vulnerabilities": [
    {
      "name": "Reentrancy Attack",
      "line_number": 25,
      "description": "External call with value transfer before state update",
      "severity": "Critical",
      "category": "Reentrancy",
      "recommendation": "Use ReentrancyGuard modifier",
      "cwe_id": "CWE-841",
      "impact": "Funds can be drained through recursive calls"
    }
  ],
  "summary": {
    "total_vulnerabilities": 1,
    "critical_count": 1,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "security_score": 70,
    "risk_level": "High Risk"
  },
  "metadata": {
    "solidity_version": "pragma solidity ^0.8.20",
    "contract_count": 2,
    "function_count": 8,
    "line_count": 45,
    "analysis_time": 0.023
  }
}
```

## 🏗️ Project Structure

```
intelligent-contract-security/
├── src/
│   ├── main.rs              # Main application and HTTP server
│   └── analysis/
│       └── mod.rs           # Vulnerability analysis engine
├── web/
│   └── index.html           # Web interface
├── vulnerable_samples/       # Vulnerable samples for testing
├── Cargo.toml               # Rust dependencies
└── README.md                # This file
```

## 🔧 Technical Details

### **Backend (Rust)**
- **Actix Web** - High-performance HTTP server
- **Serde** - JSON serialization/deserialization
- **Modular Architecture** - Extensible analysis system

### **Frontend (Web)**
- **Vanilla JavaScript** - Modern ES6+ features
- **Tailwind CSS** - Utility-first CSS framework
- **Font Awesome** - Professional icons
- **Responsive Design** - Compatible on all devices

### **Security Algorithms**
- **Pattern Matching** - Regex-based detection
- **Context Analysis** - Code context analysis
- **Severity Scoring** - Automatic risk assessment
- **CWE Mapping** - Standard security categories

## 🧪 Test Examples

Test examples available in the `vulnerable_samples/` folder:

- **ReentrancyBank.sol** - Reentrancy attack example
- **IntegerOverflowLegacy.sol** - Integer overflow example
- **TxOriginAuth.sol** - tx.origin usage error
- **SelfDestruct.sol** - Uncontrolled selfdestruct
- **SendEtherIgnore.sol** - Unchecked send usage

## 📈 Performance

- **Analysis Speed**: ~1000 lines/second
- **Memory Usage**: <50MB
- **CPU Usage**: Minimal
- **Response Time**: <100ms (average)

## 🤝 Contributing

1. **Fork** the project
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### **Development Setup**
```bash
# Development dependencies
cargo install cargo-watch
cargo install cargo-tarpaulin  # Test coverage

# Development server (auto-reload)
cargo watch -x run
```

## 🐛 Bug Reporting

- Use **GitHub Issues** to report bugs
- Include **reproducible** examples
- Share **environment** information
- Specify **expected vs actual** behavior

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Rust Community** - Excellent language and ecosystem
- **Actix Web** - High-performance web framework
- **Tailwind CSS** - Modern CSS framework
- **Open Source Community** - Continuous inspiration and support

## 📞 Contact

- **GitHub**: [@darksoftinc](https://github.com/darksoftinc)
- **Project**: [intelligent-contract-security](https://github.com/darksoftinc/intelligent-contract-security)
- **Issues**: [GitHub Issues](https://github.com/darksoftinc/intelligent-contract-security/issues)

## 🌟 Star the Project

If this project helped you, don't forget to give it a ⭐ star on GitHub!

---

**Secure your smart contracts with SolidityGuard!** 🚀
