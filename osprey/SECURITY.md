# Security Policy

## Supported Versions

Only the latest release of Osprey receives security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take the security of Osprey very seriously. If you discover a vulnerability in Osprey itself, please do NOT file a public issue.

Instead, please report it via one of the following methods:
1. Open a private draft security advisory on GitHub under the repository's "Security" tab.
2. Email the core maintainers directly at `security@osprey-project.dev`.

### What to Include
- A description of the vulnerability and its potential impact.
- Clear reproduction steps or a minimal proof of concept (PoC).
- Any relevant logs, versions, and environment details.

### Our Commitment
- We will acknowledge receipt of your report within 48 hours.
- We will provide an initial assessment and timeline within 5 business days.
- We will coordinate a coordinated public disclosure and release a patch promptly.

### Scope & Privacy Guarantees
- Osprey is strictly read-only when scanning local repositories.
- Osprey performs no code execution or imports on scanned target folders.
- Osprey contacts only public vulnerability feeds (`api.osv.dev`, `api.first.org`, `www.cisa.gov`) with strict timeouts and zero telemetry.
