# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in this project, please report it responsibly:

1. **Email:** Send a detailed report to **hiagokinlevi@protonmail.com**.
2. **GitHub Advisory:** Optionally use GitHub's private vulnerability reporting feature (Security tab → "Report a vulnerability").
3. **Include in your report:**
   - A clear description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Any suggested mitigations (optional)

## Response Timeline

- **Acknowledgment:** Within 48 hours of report receipt
- **Initial assessment:** Within 5 business days
- **Patch release (if confirmed):** Within 30 days for high/critical severity

## Scope

This project is a defensive security tool. Reports in scope include:

- Code execution vulnerabilities in the CLI or automation scripts
- Insecure handling of credentials or tokens in `.env` processing
- Path traversal or injection vulnerabilities in evidence packaging
- Unintended exposure of sensitive data in log output

Out of scope:

- Theoretical vulnerabilities without a practical attack path
- Issues in third-party dependencies (report to the upstream project)
- Findings in example/test data that is clearly synthetic

## Responsible Disclosure

We follow coordinated disclosure principles. We will credit researchers in the changelog unless anonymity is requested.
