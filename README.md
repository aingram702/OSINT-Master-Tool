# OSINT Master Tool 🛡️

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)

OSINT Master Tool is a unified intelligence gathering suite that provides a professional GUI for powerful open-source intelligence tools. It consolidates 15+ external tools and 8 built-in utilities into a single, real-time dashboard.

## 🌟 Key Features

- **Unified Interface**: Run multiple OSINT tools (Sherlock, Blackbird, SpiderFoot, theHarvester, etc.) from a single web UI.
- **Real-time Streaming**: Watch tool output in a built-in terminal via Server-Sent Events (SSE).
- **Security Hardened**:
  - **AES-256 Encryption**: All API keys are encrypted at rest using Fernet symmetric encryption.
  - **CSRF Protection**: Native protection against cross-site request forgery.
  - **SSRF Protection**: Outbound requests are validated against private IP blocklists.
  - **Input Validation**: Strict validation for IP addresses, domains, URLs, and file paths.
  - **CORS Restriction**: Cross-origin requests restricted to localhost only.
- **Dynamic Configuration**: Automatically generates settings and tool forms based on extensible Python definitions.
- **Built-in Utilities**: IP Geolocation, WHOIS/DNS lookups, HTTP Header Analysis, Hash Identification, Subdomain Finder, URL Unshortener, and Technology Detection.

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Git

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/aingram702/osint-master-tool.git
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

### External Tools (Optional)

The `SubTools/` directory contains integrations for external OSINT tools organized by category. Most tools require their own dependencies — check each tool's README for setup instructions:

| Category | Tools |
|----------|-------|
| Username Lookup | Sherlock, Blackbird, Holehe |
| Account Enumeration | Holehe, Ignorant |
| Network & Domain Recon | theHarvester, Shodan, SpiderFoot, Recon-ng |
| Social Media Scraping | SNScrape, Osintgram, InstaLooter, Telepathy |
| Data Extraction | ExifTool, Scrapy |

## 📂 Project Structure

```
osint-master-tool/
├── MasterToolDir/          # Flask application
│   ├── app.py              # Backend server & API routes
│   ├── tool_configs.py     # Tool definitions & CLI argument specs
│   ├── requirements.txt    # Python dependencies
│   └── static/             # Frontend assets
│       ├── index.html      # Single-page application
│       ├── css/style.css    # Dark cyberpunk theme
│       └── js/app.js        # Frontend logic & SSE streaming
├── SubTools/               # External OSINT tool integrations
│   ├── AccountEnumeration/
│   ├── DataExtraction/
│   ├── NetworkDomainRecon/
│   ├── SocialMediaScraping/
│   └── Username/
├── .env.example            # Environment variable template
├── LICENSE                 # MIT License
├── SECURITY.md             # Security policy & architecture
└── CONTRIBUTING.md         # Contribution guidelines
```

## 🔒 Security Note

On the first run, the application generates a unique encryption key in `MasterToolDir/.master.key`. This key is used to protect your API keys. **Do not share this key or include it in your commits.**

The `.gitignore` file is pre-configured to ignore sensitive data and local configurations. See [SECURITY.md](SECURITY.md) for full security documentation.

## ⚖️ Disclaimer

> **This tool is for educational and authorized security research purposes only.**
>
> The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have explicit permission before conducting reconnaissance on any network, domain, or individual. Unauthorized use of this tool may violate applicable laws and regulations.

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to add new tools, submit bug fixes, and contribute to the project.

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---
*Built with ❤️ for the OSINT community.*
