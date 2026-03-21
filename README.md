# SecureGuard — AI-Powered Secure Code Analyzer

> Detect vulnerabilities. Explain the risk. Fix the code. Instantly.

![Python](https://img.shields.io/badge/Python-3.13-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-green)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## What is SecureGuard?

SecureGuard is a **Static Application Security Testing (SAST)** tool 
that analyzes source code for security vulnerabilities — without 
running the application. Similar in concept to how Semgrep works 
at Google and CodeQL works at GitHub — but built from scratch in Python.

Paste your code → Get instant vulnerability report → Fix it securely.

---

## Features

- Detects **10+ vulnerability types** using Python `re` and `ast` modules
- Covers **OWASP Top 10** categories with CWE ID mapping
- **AI-powered explanations** via Claude API — explains WHY code is dangerous
- **Generates secure fixed code** automatically
- **Risk Score 0–100** — CRITICAL / HIGH / MEDIUM / LOW verdict
- **CVE Playground** — 5 real CVEs with exploit + patch walkthrough
- **Flask web dashboard** — paste code, see results instantly
- Downloadable HTML security report

---

## Vulnerabilities Detected

| Rule ID | Vulnerability | Severity | CWE |
|---------|--------------|----------|-----|
| SG001 | Hardcoded Password | CRITICAL | CWE-798 |
| SG002 | SQL Injection | CRITICAL | CWE-89 |
| SG003 | Dangerous eval() | HIGH | CWE-95 |
| SG004 | Dangerous exec() | CRITICAL | CWE-78 |
| SG005 | Command Injection | CRITICAL | CWE-78 |

---

## Tech Stack

- **Python 3.13** — Core scanning logic
- **re + ast** — Pattern matching and syntax tree parsing (SAST)
- **Anthropic Claude API** — AI explanations and secure code generation
- **Flask** — Web server and dashboard
- **Jinja2** — HTML report templates

---

## Project Structure
```
secureguard/
├── modules/
│   ├── sast_engine.py      # SAST rule engine (regex + AST)
│   ├── ai_reviewer.py      # Claude API integration
│   ├── risk_scorer.py      # Risk scoring algorithm
│   └── cve_playground.py   # Real CVE demonstrations
├── templates/              # Flask HTML templates
├── static/                 # CSS styling
├── cve_data/               # CVE JSON database
├── scanner_core.py         # Module integration pipeline
├── app.py                  # Flask web application
└── requirements.txt
```

---

## Installation
```bash
# Clone the repository
git clone https://github.com/Ved-0604/secureguard.git
cd secureguard

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Mac/Linux
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

Open browser: `http://localhost:5000`

---

## Quick Demo
```python
# Paste this vulnerable code into SecureGuard:
def login(username):
    password = "admin@123"          # Hardcoded credential
    query = "SELECT * FROM users "
            "WHERE name='" + username + "'"  # SQL Injection
    eval(user_input)                # Code injection
```

**SecureGuard output:**
```
[CRITICAL] Hardcoded Password — Line 2 — CWE-798
[CRITICAL] SQL Injection      — Line 3 — CWE-89
[HIGH]     Dangerous eval()   — Line 4 — CWE-95

Risk Score: 80/100 — CRITICAL RISK
```

---

## Ethical Usage

This tool is designed for:
- Analyzing **your own code** before deployment
- **Educational purposes** and learning secure coding
- Use on platforms like DVWA, HackTheBox, TryHackMe

**Never use this tool on code or systems you don't own or have 
explicit permission to test.**

---

## Team

| Member | Role |
|--------|------|
| Ved Sharma | SAST Engine + Flask Dashboard |
| Yash Jain | AI Integration + Risk Scorer |
| Mukund Ranjan | CVE Playground + Documentation |

**Mentor:** Prof. K. K. Sharma — HoD, IT, SGSITS Indore

---

## Academic Context

**Department of Information Technology**  
Shri Govindram Seksaria Institute of Technology and Science (SGSITS)  
Indore, Madhya Pradesh — B.E. Third Year — 2025–26

---

*Built with focus on real-world AppSec concepts — 
not just another tutorial project.*