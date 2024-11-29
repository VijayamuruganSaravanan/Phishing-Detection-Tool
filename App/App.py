import tkinter as tk
from tkinter import ttk, messagebox
import requests
import configparser
import re
import socket
import os

# Load API Keys from config.ini
config = configparser.ConfigParser()
config.read("config.ini")

# API keys
VT_API_KEY = config["VirusTotal"]["API_KEY"]
AIPDB_API_KEY = config["AbuseIPDB"]["API_KEY"]
IPINFO_API_KEY = config["IPinfo"]["API_KEY"]
IPQS_API_KEY = config["IPQS"]["API_KEY"]

VT_HEADERS = {"x-apikey": VT_API_KEY}
AIPDB_HEADERS = {"Key": AIPDB_API_KEY, "Accept": "application/json"}
IPQS_HEADERS = {"key": IPQS_API_KEY}

history_file = "history.txt"

# Helper Functions
def is_url(value):
    """Determine if the input is a URL."""
    regex = re.compile(r"^(https?://)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,6}(\.[a-zAZ]{2,6})?(/[^\s]*)?$")
    return bool(regex.match(value))


def is_ip(value):
    """Determine if the input is an IP address."""
    # Simple check for IP address format x.x.x.x (numbers between 0 and 255)
    regex = re.compile(r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    return bool(regex.match(value))


def url_to_ip(url):
    """Convert URL to IP address."""
    try:
        ip = socket.gethostbyname(url)
        return ip
    except socket.error:
        return None


def analyze_with_virustotal(url):
    """Analyze a URL with VirusTotal."""
    submit_url = "https://www.virustotal.com/api/v3/urls"
    data = {"url": url}
    response = requests.post(submit_url, headers=VT_HEADERS, data=data)
    if response.status_code == 200:
        result = response.json()
        analysis_id = result["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        result_response = requests.get(analysis_url, headers=VT_HEADERS)
        if result_response.status_code == 200:
            stats = result_response.json()["data"]["attributes"]["stats"]
            return {
                "harmless": stats["harmless"],
                "malicious": stats["malicious"],
                "suspicious": stats["suspicious"],
                "undetected": stats["undetected"],
            }
    return {"error": "VirusTotal could not analyze the input."}


def analyze_with_abuseipdb(ip):
    """Analyze an IP address with AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=AIPDB_HEADERS, params=params)
    if response.status_code == 200:
        data = response.json()["data"]
        return {
            "ip": data["ipAddress"],
            "abuse_confidence": data["abuseConfidenceScore"],
            "total_reports": data["totalReports"],
            "last_reported": data["lastReportedAt"],
        }
    return {"error": "AbuseIPDB could not analyze the input."}


def analyze_with_ipinfo(ip):
    """Analyze an IP address with IPinfo."""
    url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return {
            "ip": data.get("ip"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "organization": data.get("org"),
        }
    return {"error": "IPinfo could not analyze the input."}


def analyze_with_ipqs(ip):
    """Analyze an IP address with IPQualityScore."""
    url = f"https://ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return {
            "ip": data.get("ip"),
            "fraud_score": data.get("fraud_score"),
            "is_phishing": data.get("is_phishing"),
        }
    return {"error": "IPQualityScore could not analyze the input."}


def generate_report(input_value, results, phishing_status):
    """Generate a comprehensive report based on results."""
    report = [f"Analysis Report for Input: {input_value}\n"]
    for section, data in results.items():
        if isinstance(data, dict):
            report.append(f"\n{section.replace('_', ' ').title()} Analysis:")
            for key, value in data.items():
                report.append(f"  - {key.replace('_', ' ').title()}: {value}")
        else:
            report.append(f"\n{section.replace('_', ' ').title()}: {data}")
    report.append("\nFinal Verdict:")
    report.append(f"  {phishing_status}")
    return "\n".join(report)


def save_to_history(input_value, report):
    """Save analysis to history as a text file."""
    if not os.path.exists(history_file):
        with open(history_file, "w", encoding="utf-8") as file:
            file.write("Phishing Detection History:\n\n")

    with open(history_file, "a", encoding="utf-8") as file:
        file.write(f"--- Analysis {len(open(history_file, 'r').readlines()) // 10 + 1} ---\n")
        file.write(f"Input: {input_value}\n")
        file.write(report + "\n\n")


def determine_phishing_for_ip(results):
    """Determine if an IP is phishing based on AbuseIPDB and IPQualityScore."""
    abuse_score = results.get("AbuseIPDB", {}).get("abuse_confidence", 0)
    fraud_score = results.get("IPQualityScore", {}).get("fraud_score", 0)

    if abuse_score > 85 or fraud_score > 90:
        return "Phishing Site (High Risk)"
    elif 50 <= abuse_score <= 85 or 50 <= fraud_score <= 90:
        return "Slight Chance of Phishing (Medium Risk)"
    else:
        return "Probably Safe (Low Risk)"


def determine_phishing_for_url(results):
    """Determine if a URL is phishing based on VirusTotal feedback."""
    vt_data = results.get("VirusTotal", {})
    if isinstance(vt_data, dict):
        malicious = vt_data.get("malicious", 0)
        suspicious = vt_data.get("suspicious", 0)
        if malicious > 5 or suspicious > 10:
            return "Phishing Site (High Risk)"
        elif malicious > 0 or suspicious > 0:
            return "Slight Chance of Phishing (Medium Risk)"
    return "Probably Safe (Low Risk)"


def analyze_input():
    """Analyze the user input."""
    input_value = input_field.get().strip()
    if not input_value:
        messagebox.showerror("Error", "Please enter a valid URL or IP address.")
        return

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "Analyzing input... Please wait.\n\n")

    results = {}

    if is_url(input_value):
        # Analyze URL with VirusTotal
        results["VirusTotal"] = analyze_with_virustotal(input_value)

        # Analyze URL with IPQualityScore
        results["IPQualityScore"] = analyze_with_ipqs(input_value)

        # Convert URL to IP
        ip_address = url_to_ip(input_value)
        if ip_address:
            results["Converted_IP"] = {"Converted IP": ip_address}
            # Analyze IP with other APIs (AbuseIPDB and IPInfo)
            results["IPinfo"] = analyze_with_ipinfo(ip_address)
            results["AbuseIPDB"] = analyze_with_abuseipdb(ip_address)
            # Determine phishing status for IP
            phishing_status = determine_phishing_for_ip(results)
        else:
            # Use only VirusTotal and IPQS for URL analysis (if cannot convert URL to IP)
            phishing_status = determine_phishing_for_url(results)
    elif is_ip(input_value):
        # Analyze IP address with IPQualityScore
        results["IPQualityScore"] = analyze_with_ipqs(input_value)
        # Analyze IP with AbuseIPDB
        results["AbuseIPDB"] = analyze_with_abuseipdb(input_value)
        # Analyze IP with IPInfo
        results["IPinfo"] = analyze_with_ipinfo(input_value)
        # Determine phishing status for IP
        phishing_status = determine_phishing_for_ip(results)
    else:
        messagebox.showerror("Error", "Invalid URL or IP address format.")
        return

    # Generate the report
    report = generate_report(input_value, results, phishing_status)
    result_text.insert(tk.END, report)
    save_to_history(input_value, report)


def clear_input():
    """Clear the input field and result text."""
    input_field.delete(0, tk.END)
    result_text.delete(1.0, tk.END)


def show_history():
    """Show analysis history in a popup window."""
    if not os.path.exists(history_file):
        messagebox.showinfo("History", "No history found.")
        return

    # Create a new popup window for history
    history_window = tk.Toplevel(root)
    history_window.title("Analysis History")
    history_window.geometry("600x400")  # Set an appropriate size for the window

    # Create a frame to hold the content and buttons
    history_frame = ttk.Frame(history_window, padding="10")
    history_frame.pack(fill="both", expand=True)

    # Text widget to display history content
    text = tk.Text(history_frame, wrap="word", font=("Arial", 10))
    text.pack(side="left", fill="both", expand=True, padx=5, pady=5)

    # Scrollbar for the Text widget
    scrollbar = ttk.Scrollbar(history_frame, orient="vertical", command=text.yview)
    scrollbar.pack(side="right", fill="y")
    text.config(yscrollcommand=scrollbar.set)

    # Load and display the content of the history file
    with open(history_file, "r", encoding="utf-8") as file:
        text.insert("1.0", file.read())


    # Allow the user to close the history window
    def close_history():
        history_window.destroy()

    ttk.Button(history_frame, text="Close", command=close_history).pack(pady=5)

    # Disable resizing for cleaner UI
    history_window.resizable(False, False)



# GUI Setup
root = tk.Tk()
root.title("Phishing Detection Tool")
root.geometry("800x600")  # Set initial window size

# Configure root rows and columns for resizing
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

# Create a frame to hold all widgets
main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0, sticky="nsew")

# Configure rows and columns of main_frame for proper alignment
main_frame.grid_rowconfigure(3, weight=1)
main_frame.grid_columnconfigure(0, weight=1)

# Add widgets
ttk.Label(main_frame, text="Enter URL or IP Address:", font=("Arial", 12)).grid(row=0, column=0, sticky="w", pady=5)

input_field = ttk.Entry(main_frame, font=("Arial", 10))
input_field.grid(row=1, column=0, sticky="ew", pady=5)

button_frame = ttk.Frame(main_frame)
button_frame.grid(row=2, column=0, sticky="ew", pady=5)

ttk.Button(button_frame, text="Analyze", command=analyze_input).pack(side="left", padx=5)
ttk.Button(button_frame, text="Clear", command=clear_input).pack(side="left", padx=5)
ttk.Button(button_frame, text="View History", command=show_history).pack(side="left", padx=5)

result_text = tk.Text(main_frame, wrap="word", height=15, font=("Arial", 10))
result_text.grid(row=3, column=0, sticky="nsew", padx=5, pady=5)

root.mainloop()
