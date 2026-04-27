# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in OSINT Master Tool, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **aingram702@hide702.aleeas.com**

Include the following in your report:
- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Suggested fix (if any)

I will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Security Architecture

### Encryption
- **API Key Storage**: All API keys are encrypted at rest using Fernet symmetric encryption (AES-128-CBC with HMAC-SHA256).
- **Master Key**: A unique encryption key (`.master.key`) is generated on first run and stored locally with owner-only file permissions. This key never leaves your machine.

### Access Controls
- **CSRF Protection**: All state-changing endpoints require a valid CSRF token via the `X-OSINT-CSRF` header.
- **CORS Restriction**: Cross-origin requests are restricted to localhost only (`127.0.0.1:5000` and `localhost:5000`).
- **Input Validation**: Strict regex validation for IP addresses, domains, and URLs. Path traversal protection on all parameters.

### Network Security
- **SSRF Protection**: Built-in tools that make outbound HTTP requests validate that target URLs do not resolve to private/internal IP addresses.
- **Local Binding**: The Flask server binds to `127.0.0.1` by default, preventing external network access.

### What is NOT in Scope
- Vulnerabilities in third-party tools integrated via the `SubTools/` directory (Sherlock, Blackbird, etc.) — please report those to their respective maintainers.
- Issues that require physical access to the machine running the tool.

## Best Practices for Users

1. **Never expose this tool to the public internet.** It is designed for local use only.
2. **Protect your `.master.key` file.** Do not share it or include it in version control.
3. **Keep dependencies updated.** Run `pip install --upgrade -r MasterToolDir/requirements.txt` regularly.
4. **Use a virtual environment** to isolate dependencies from your system Python.
5. **Review tool output carefully.** OSINT tools interact with external services and may generate network traffic.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Active support  |
