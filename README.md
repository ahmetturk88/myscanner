# 🛡️ MyScanner

> 🚧 **This project is currently under active development.**

A comprehensive cybersecurity platform for scanning URLs, files, domains,
emails, and IP addresses for threats — powered by open threat intelligence
sources including **url.vet**, **MalwareBazaar**, and **Hybrid Analysis**.

## 🌐 Live Demo
- **Website:** https://myscanners.com
- **Email:** info@myscanners.com

## 🛠️ Tech Stack
- 🐍 **Python / Flask** — Web framework
- 🗄️ **PostgreSQL** — Production database (Render)
- ⚡ **Celery + Redis** — Background task queue
- 🎨 **HTML / CSS / JavaScript** — Frontend
- 🐳 **Docker** — For self-hosted services (url.vet)

## 🔬 Threat Intelligence Sources
- **url.vet** — Open-source URL analysis (AGPL-3.0)
- **MalwareBazaar** (abuse.ch) — File hash intelligence
- **Hybrid Analysis** — Behavioral sandbox (development)
- **AbuseIPDB** — IP reputation
- **Local static analysis** — Custom MyScanner engine

## ✅ Current Features

### URL & Web
- ✅ URL Scanner — full analysis of any URL
- ✅ QR Code Scanner — extract and scan URLs from QR codes
- ✅ Subdomain Finder — enumerate subdomains
- ✅ Site Scanner — comprehensive website analysis
- ✅ SSL Checker — certificate validation

### Files & Malware
- ✅ File Scanner — malware analysis with 5 hash types + YARA rules
- ✅ Sandbox Analyzer — behavioral analysis (file / hash / URL)
- ✅ PDF Report Generator — professional reports

### Network & Identity
- ✅ Domain Lookup — WHOIS, DNS, registrar info
- ✅ IP Checker — reputation via AbuseIPDB
- ✅ Email Checker — MX, SPF, DMARC, disposable detection

### Account & Admin
- ✅ User authentication (register / login / email verification)
- ✅ Daily scan quotas per role
- ✅ Admin panel + activity logs
- ✅ PDF export of reports

## 🚧 In Progress
- 🔄 Vulnerability Scanner (OpenVAS integration)
- 🔄 Advanced malware sandbox (Cuckoo)
- 🔄 Public API for developers

## 📦 Installation (Development)

```bash
# Clone the repository
git clone <your-repo-url>
cd flask_app

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys

# Run the app
python app.py