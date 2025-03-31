# 🔐 Keylogger Detection Tool (Python + Tkinter)

A simple GUI-based tool to scan for suspicious keylogger-like processes and known malicious hashes on your system.

## 🖥️ Features
- Detects suspicious process names (e.g., `keylogger`, `hook`, etc.)
- Scans running executables and checks their SHA-256 hash
- Compares against a known list of malicious hashes
- Logs findings to a file (`detection_log.txt`)
- Simple GUI using Python's built-in `tkinter`

## 🚀 How to Run
1. Make sure Python 3.x is installed
2. Install dependencies:
   ```bash
   pip install psutil
