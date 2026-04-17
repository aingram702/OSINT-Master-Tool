# OSINT Master Tool 🛡️

OSINT Master Tool is a unified intelligence gathering suite that provides a professional GUI for powerful open-source intelligence tools. It consolidates 15+ external tools and 8 built-in utilities into a single, real-time dashboard.

## 🌟 Key Features

- **Unified Interface**: Run multiple OSINT tools (Sherlock, Blackbird, SpiderFoot, theHarvester, etc.) from a single web UI.
- **Real-time Streaming**: Watch tool output in a built-in terminal via Server-Sent Events (SSE).
- **Security Hardened**:
  - **AES-256 Encryption**: All API keys are encrypted at rest using Fernet symmetric encryption.
  - **CSRF Protection**: Native protection against cross-site request forgery.
  - **Input Validation**: Strict validation for IP addresses, domains, and URLs.
  - **Path Safety**: Built-in protection against path traversal attacks.
- **Dynamic Configuration**: Automatically generates settings and tool forms based on extensible JSON definitions.
- **Built-in Utilities**: IP Geolocation, WHOIS/DNS lookups, HTTP Header Analysis, Hash Identification, and more.

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Node.js (Optional, for advanced frontend development)
- Git

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/osint-master-tool.git
   cd osint-master-tool
   ```

2. **Install dependencies:**
   ```bash
   pip install -r MasterToolDir/requirements.txt
   ```

3. **Run the application:**
   ```bash
   python MasterToolDir/app.py
   ```

4. **Access the UI:**
   Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

## 📂 Project Structure

- `MasterToolDir/`: Main Flask application, static assets, and configurations.
- `SubTools/`: Integration directory for external OSINT tools (organized by category).
- `static/`: Modern, responsive CSS and dynamic JavaScript logic.

## 🔒 Security Note

On the first run, the application generates a unique encryption key in `MasterToolDir/.master.key`. This key is used to protect your API keys. **Do not share this key or include it in your commits.**

The `.gitignore` file is pre-configured to ignore sensitive data and local configurations.

## ⚖️ Disclaimer

This tool is for educational and authorized security research purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have permission before conducting reconnaissance on any network or individual.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an issue for bugs and feature requests.

---
*Built with ❤️ for the OSINT community.*
