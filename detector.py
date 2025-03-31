import psutil
import hashlib
import os
from datetime import datetime
import tkinter as tk
from tkinter import scrolledtext

# ====== SETTINGS ======
suspicious_names = ['keylogger', 'kl.exe', 'logger', 'hook', 'spy']
known_bad_hashes = [
    "abc123deadbeef",
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
]
log_file = "detection_log.txt"

# ====== FUNCTIONS ======

def hash_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def scan_processes():
    output_box.delete('1.0', tk.END)
    suspicious_count = 0
    now = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    output_box.insert(tk.END, f"{now} 🔍 Starting scan...\n\n")

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            name = proc.info['name'].lower()
            path = proc.info['exe'] or "Unknown"
            flagged = False

            if any(susp in name for susp in suspicious_names):
                msg = f"⚠️ Suspicious name: {name} (PID {proc.pid}) - {path}"
                output_box.insert(tk.END, msg + "\n")
                flagged = True

            if path and os.path.isfile(path):
                file_hash = hash_file(path)
                if file_hash and file_hash in known_bad_hashes:
                    msg = f"🚨 Malicious hash: {name} (PID {proc.pid}) - {path}"
                    output_box.insert(tk.END, msg + "\n")
                    flagged = True

            if flagged:
                suspicious_count += 1

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if suspicious_count == 0:
        output_box.insert(tk.END, "\n✅ No suspicious processes found.\n")
    else:
        output_box.insert(tk.END, f"\n⚠️ Total suspicious processes found: {suspicious_count}\n")

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(output_box.get("1.0", tk.END) + "\n")

# ====== GUI SETUP ======

window = tk.Tk()
window.title("Keylogger Detection Tool")
window.geometry("700x400")

title_label = tk.Label(window, text="🔐 Keylogger Detection Tool", font=("Helvetica", 16))
title_label.pack(pady=10)

start_button = tk.Button(window, text="Start Scan", command=scan_processes, bg="green", fg="white", padx=10, pady=5)
start_button.pack()

output_box = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=80, height=18, font=("Consolas", 10))
output_box.pack(padx=10, pady=10)

window.mainloop()
