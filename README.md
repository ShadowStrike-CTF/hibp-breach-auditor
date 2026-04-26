# HaveIBeenPwned Breach Auditor

**Version 1.0.0**

A Python CLI tool to check email addresses and passwords against the HaveIBeenPwned breach database. Uses k-anonymity for password checks, ensuring your credentials never leave your machine.

## Features

- **Password checking with k-anonymity:** Safely check passwords without transmitting them — **no API key required, completely free**
- **Email breach checking:** Query HIBP API v3 for known compromises (requires paid API subscription)
- **Detailed breach information:** Show breach names, dates, exposed data types
- **Report generation:** Optional timestamped `.txt` output
- **Rate limit handling:** Graceful error handling and courtesy delays

## Why K-Anonymity Matters

When checking passwords, this tool:
1. Hashes your password locally using SHA-1
2. Sends **only the first 5 characters** of the hash to HIBP
3. Receives ~500-1000 matching hash suffixes
4. Checks locally if your full hash is in that list

The HIBP API never sees your actual password or even your complete hash.

## Installation

```bash
pip install requests
git clone https://github.com/ShadowStrike-CTF/hibp-breach-auditor.git
cd hibp-breach-auditor
```

### ⚠️ Security: Read Before Running

**Before executing this script:**
- Read the entire source code
- Verify API endpoints and data handling
- Check for unexpected network calls or file operations

**ABC principle:** Assume nothing. Believe nothing. Check everything.

You are responsible for verifying any code before execution.

---

## Usage

### Check Password (No API Key Needed)

```bash
python hibp_auditor.py --password "YourPassword123"
```

**Free and instant** - uses k-anonymity to check safely.

### Check Email (Requires Paid API Key)

```bash
python hibp_auditor.py --email test@example.com --api-key YOUR_API_KEY
```

Get a paid API key at [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)

```bash
python hibp_auditor.py --password "YourPassword123"
```

No API key needed - uses k-anonymity for privacy.

### Save Report

```bash
python hibp_auditor.py --email test@example.com --api-key YOUR_KEY --output report.txt
```

## Sample Output

**Password check (no API key needed):**
```
[*] Checking password (using k-anonymity)...
[WARNING] Password found in 2,254,650 breaches!
[ADVICE] This password is compromised - change it immediately

[*] Audit complete
```

Or if clean:
```
[OK] Password not found in known breaches
```

**Email check (requires paid API key):**
```
[*] Checking email: test@example.com
[WARNING] Found in 3 breach(es):

  Breach: Adobe
  Domain: adobe.com
  Date: 2013-10-04
  Accounts: 152,445,165
  Data: Email addresses, Password hints, Passwords, Usernames
```

**Password check:**
```
[*] Checking password (using k-anonymity)...
[WARNING] Password found in 2,417 breaches!
[ADVICE] This password is compromised - change it immediately
```

Or if clean:
```
[OK] Password not found in known breaches
```

## Use Cases

- **Team audits:** Check all company email addresses for compromised accounts
- **Password policy:** Validate passwords against known breaches before allowing them
- **Incident response:** Investigate suspected credential exposure
- **Security training:** Demonstrate password reuse risks to users

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `--email` | No* | Email address to check |
| `--password` | No* | Password to check (uses k-anonymity) |
| `--api-key` | For email | HIBP API key |
| `--output` | No | Write results to file |

*At least one of `--email` or `--password` must be provided

## Requirements

- Python 3.6+
- `requests` library
- **No API key needed** for password checking
- Paid HIBP API subscription required for email breach checking

## Security Best Practices

- Store API keys in environment variables, not in scripts
- Never log actual passwords - the script outputs `[REDACTED]`
- Respect HIBP rate limits (free service - don't abuse it)
- TLS verification is enabled by default - don't disable it

## Tutorial

Read the full tutorial on DEV Community: [How to Build a HaveIBeenPwned Breach Auditor in Python](https://dev.to/shadowstrike/how-to-build-a-haveibeenpwned-breach-auditor-in-python-241g)

## License

MIT License - See LICENSE file for details

## Author

Built by **ShadowStrike** (Strategos) — where we build actual security tools instead of theatre 🎃. 

Part of the Strategos project for APAC forensic and security tooling.
