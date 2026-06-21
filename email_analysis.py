import re
from urllib.parse import urlparse
from tkinter import Tk, Button, Text, filedialog, END, Label

def extract_headers(content):
    headers = {}

    for line in content.split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

    return headers

def analyze_email(file_path, output):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        output.delete(1.0, END)
        output.insert(END, "=== ADVANCED EMAIL ANALYSIS ===\n\n")

        headers = extract_headers(content)

        # Show headers
        output.insert(END, "[HEADERS]\n")
        for key in ["From", "To", "Subject"]:
            if key in headers:
                output.insert(END, f"{key}: {headers[key]}\n")

        # Extract sender domain
        sender_domain = ""
        if "From" in headers:
            match = re.search(r'@([\w\.-]+)', headers["From"])
            if match:
                sender_domain = match.group(1)

        # Extract URLs
        urls = re.findall(r'(https?://[^\s]+)', content)

        output.insert(END, "\n[URL ANALYSIS]\n")
        for url in urls:
            parsed = urlparse(url)
            output.insert(END, f"URL: {url}\n")

            # Domain mismatch detection
            if sender_domain and sender_domain not in parsed.netloc:
                output.insert(END, "⚠ ALERT: Domain mismatch detected\n")

            # IP based URL detection
            if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
                output.insert(END, "⚠ ALERT: IP-based URL detected\n")

            # Suspicious keywords in URL
            suspicious_words = ["login", "verify", "update", "bank"]
            for word in suspicious_words:
                if word in url.lower():
                    output.insert(END, f"⚠ ALERT: Suspicious keyword found in URL -> {word}\n")

        # Mail flow tracking
        received_lines = re.findall(r"Received:.*", content)
        output.insert(END, "\n[MAIL FLOW]\n")

        for r in received_lines:
            output.insert(END, r + "\n")

        # IP extraction
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)

        output.insert(END, "\n[IP ADDRESSES]\n")

        for ip in set(ips):
            output.insert(END, f"{ip}\n")

        # Phishing keyword detection
        keywords = [
            "urgent",
            "verify",
            "login",
            "reset",
            "bank",
            "otp",
            "password",
            "click here"
        ]

        found = [k for k in keywords if k in content.lower()]

        if found:
            output.insert(END, "\n⚠ ALERT: Phishing Keywords Found\n")

            for f in found:
                output.insert(END, f"- {f}\n")

        # Attachment detection
        suspicious_files = [".exe", ".zip", ".scr", ".bat", ".js"]

        for ext in suspicious_files:
            if ext in content.lower():
                output.insert(END, f"\n⚠ ALERT: Suspicious Attachment Detected ({ext})\n")

        # Email spoofing check
        if "Reply-To" in headers and "From" in headers:
            if headers["Reply-To"] != headers["From"]:
                output.insert(END, "\n⚠ ALERT: Possible Email Spoofing Detected\n")

        # Final verdict
        output.insert(END, "\n=== FINAL ANALYSIS ===\n")

        risk_score = 0

        if found:
            risk_score += 2

        if len(urls) > 0:
            risk_score += 2

        if suspicious_files:
            risk_score += 2

        if risk_score >= 4:
            output.insert(END, "⚠ RESULT: HIGHLY SUSPICIOUS EMAIL\n")
        elif risk_score >= 2:
            output.insert(END, "⚠ RESULT: SUSPICIOUS EMAIL\n")
        else:
            output.insert(END, "✓ RESULT: LIKELY SAFE\n")

    except Exception as e:
        output.insert(END, f"Error: {str(e)}")

def open_file():
    path = filedialog.askopenfilename(
        title="Select Email File",
        filetypes=[("Email Files", "*.txt *.eml"), ("All Files", "*.*")]
    )

    if path:
        analyze_email(path, output_box)

# GUI
root = Tk()
root.title("Advanced SOC Email Analyzer")
root.geometry("850x600")

Label(
    root,
    text="SOC Email Analyzer - Phishing & Header Analysis",
    font=("Arial", 14)
).pack(pady=10)

Button(
    root,
    text="Upload Email File",
    command=open_file
).pack(pady=10)

output_box = Text(root, height=40, width=120)
output_box.pack(pady=10)

root.mainloop()