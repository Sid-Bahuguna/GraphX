# GraphQL Vulnerability Scanner

A **comprehensive** security testing tool for GraphQL APIs. This scanner implements **ALL known GraphQL vulnerabilities** based on OWASP guidelines and latest security research.


## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/Sid-Bahuguna/GraphX.git
cd GraphX

# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/macOS)
chmod +x graphql_scanner.py
```

## 💻 Usage

### Basic Full Scan
```bash
python graphql_scanner.py -u https://example.com/graphql
```

### Quick Scan (Skip Time-Intensive Tests)
```bash
python graphql_scanner.py -u https://example.com/graphql --quick
```

### Authenticated Scan
```bash
python graphql_scanner.py -u https://api.example.com/graphql \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Full Scan with Multiple Headers
```bash
python graphql_scanner.py -u https://api.example.com/graphql \
  -H "Authorization: Bearer token123" \
  -H "X-API-Key: key456" \
  -H "User-Agent: SecurityScanner/2.0" \
  --full
```

## 🔒 Security & Ethics

### Authorized Testing Only
- Obtain written permission before scanning
- Comply with all applicable laws
- Follow responsible disclosure practices
- Do not use against production systems without authorization

### Legal Disclaimer
This tool is for **authorized security testing only**. Unauthorized use may be illegal. Users are solely responsible for compliance with all applicable laws and regulations.


## 📈 Roadmap

- [ ] JSON/HTML/PDF report export
- [ ] WebSocket subscription testing
- [ ] GraphQL over WebSocket support
- [ ] Custom vulnerability plugins
- [ ] Integration with Burp Suite/ZAP
- [ ] Machine learning anomaly detection
- [ ] Multi-threaded scanning
- [ ] REST to GraphQL converter testing
- [ ] Federation-specific vulnerabilities
- [ ] Apollo-specific security checks

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## ⚠️ Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

The authors assume no liability for misuse. Users must:
- Obtain explicit written permission
- Comply with all laws and regulations
- Use responsibly and ethically
- Follow responsible disclosure

## 📚 References

- [GraphQL Security Best Practices](https://graphql.org/learn/best-practices/)
- [GraphQL Authorization Guide](https://graphql.org/learn/authorization/)
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

---

**Built with ❤️ by Sidharth Bahuguna**

*Version 2.0 - GraphQL Security Scanner*

*Last Updated: December 2025*
