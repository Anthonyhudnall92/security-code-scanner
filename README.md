# 🛡️ Security Code Scanner

A comprehensive security scanning tool that generates professional HTML reports with CVE references and remediation guidance.

## ✨ Features

- **Comprehensive Security Scanning**: Uses Semgrep with multiple rule sets including:
  - Secrets detection (API keys, passwords, tokens)
  - OWASP Top 10 vulnerabilities
  - CWE Top 25 security issues
  - Security audit rules
  - Supply chain security checks

- **Professional HTML Reports**: 
  - Executive summary with severity metrics
  - Detailed findings with file locations and line numbers
  - CVE references and security guidance
  - Actionable remediation steps
  - Modern, responsive design

- **User-Friendly Interface**:
  - Color-coded terminal output
  - Progress indicators
  - Automatic browser opening
  - Report cleanup functionality

## 🚀 Quick Start

### Prerequisites

- macOS with Homebrew installed
- Python 3.x
- Semgrep (automatically checked and installation guided)

### Installation

1. Clone this repository:
```bash
git clone https://github.com/Anthonyhudnall92/security-code-scanner.git
cd security-code-scanner
```

2. Make scripts executable:
```bash
chmod +x security-scan-html.sh generate_html_report.py
```

3. Install Semgrep (if not already installed):
```bash
brew install semgrep
```

### Usage

#### Basic Scan
Scan current directory and open HTML report:
```bash
./security-scan-html.sh
```

#### Advanced Usage
```bash
# Scan specific directory
./security-scan-html.sh /path/to/project

# Scan without opening browser
./security-scan-html.sh . --no-open

# Scan with cleanup of old reports
./security-scan-html.sh . --cleanup

# View help
./security-scan-html.sh --help
```

## 📊 Output

The scanner generates two types of output:

1. **JSON Report** (`semgrep_results_TIMESTAMP.json`): Raw Semgrep output for integration
2. **HTML Report** (`security_report_TIMESTAMP.html`): Professional report with:
   - Executive dashboard
   - Severity-based findings
   - Remediation guidance
   - Security references

## 🔧 Components

### `security-scan-html.sh`
Main script that orchestrates the security scan:
- Dependency checking
- Comprehensive Semgrep scanning
- HTML report generation
- User interface and options

### `generate_html_report.py`
Python script that converts JSON results to HTML:
- Parses Semgrep JSON output
- Applies security guidance based on vulnerability types
- Generates professional HTML reports
- Includes CVE references and remediation steps

## 📈 Sample Output

### Terminal Output
```
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  SECURITY SCANNER                       ║
║              Comprehensive Code Security Analysis            ║
╚══════════════════════════════════════════════════════════════╝

🔍 Checking dependencies...
✅ All dependencies satisfied
🚀 Starting security scan...
```

### HTML Report Features
- **Dashboard**: Summary cards showing findings by severity
- **Detailed Findings**: Each issue includes:
  - Vulnerability description
  - File location and line numbers
  - Severity badge
  - Remediation steps
  - OWASP/CWE references
- **Professional Design**: Clean, modern interface with responsive layout

## 🛠️ Configuration

The scanner uses multiple Semgrep rule sets by default:
- `p/secrets`: Detects hardcoded secrets
- `p/security-audit`: General security vulnerabilities
- `p/owasp-top-ten`: OWASP Top 10 compliance
- `p/cwe-top-25`: CWE Top 25 security issues
- `p/supply-chain`: Supply chain security

## 📝 Security Guidance Database

The tool includes built-in remediation guidance for:
- **Secrets**: Hardcoded API keys, passwords, tokens
- **Injection**: SQL injection, command injection vulnerabilities
- **XSS**: Cross-site scripting vulnerabilities
- **General Security**: Other security vulnerabilities

Each finding includes:
- Description of the security issue
- Step-by-step remediation instructions
- Links to OWASP and security resources

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit your changes (`git commit -m 'Add some amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 🙋‍♂️ Support

For issues or questions:
1. Check existing [GitHub Issues](https://github.com/Anthonyhudnall92/security-code-scanner/issues)
2. Create a new issue with detailed description
3. Include scan output and environment details

---

**Built with ❤️ for secure code development**
