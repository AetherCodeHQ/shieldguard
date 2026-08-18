# 🛡️ ShieldGuard-CLI

![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat&logo=go)
![Ollama](https://img.shields.io/badge/LLM-Ollama-black?style=flat&logo=ollama)

[![ShieldGuard CI](https://github.com/Qyroxen/shieldguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Qyroxen/shieldguard/actions/workflows/ci.yml)

**ShieldGuard** is a local-first Static Application Security Testing (SAST) CLI tool built with Go. It scans codebases for high-risk security vulnerabilities and uses local LLMs via **Ollama** to analyze risks and auto-patch vulnerable code lines.

---

## ✨ Features

- **🔒 Local-First Security:** Zero cloud dependency — code analysis and LLM remediation run entirely on your local machine.
- **⚡ Fast SAST Scanning:** Pattern matching engine for common security anti-patterns (Hardcoded Secrets, Command Injections, SQL Injections).
- **🤖 LLM-Powered Auto-Fix:** Integration with Ollama models (e.g., `llama3`) to explain vulnerabilities and automatically apply patches with `--auto-fix`.
- **🎨 Colored CLI UI:** Clean, human-readable terminal output powered by Cobra and Color.

---

## 🛠️ Architecture

```
[ Local Codebase ] ──> ( ShieldGuard SAST Scanner ) ──> [ Found Vulnerabilities ]
                                                               |
                                                               v
[ Patched Codebase ] <── ( Auto-Fix Engine ) <─── [ Local Ollama API (Llama3) ]
```

---

## 🚀 Quick Start

### 1. Prerequisites

- [Go 1.23+](https://go.dev/dl/) installed.
- [Ollama](https://ollama.ai/) running locally with your model of choice:
  ```bash
  ollama pull llama3
  ollama serve
  ```

### 2. Build

```bash
git clone [https://github.com/Qyroxen/shieldguard.git](https://github.com/Qyroxen/shieldguard.git)
cd shieldguard
go mod tidy
go build -o shieldguard.exe main.go
```

### 3. Usage

**Basic Scan:**
```bash
.\shieldguard.exe scan --path ./examples/vulnerable-app
```

**Scan with Auto-Fix (LLM Remediation):**
```bash
.\shieldguard.exe scan --path ./examples/vulnerable-app --model llama3 --auto-fix
```

---

## 📜 License

This project is licensed under the MIT License.
