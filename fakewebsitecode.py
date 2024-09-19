import tkinter as tk
from tkinter import ttk
import requests
import ssl
import socket
import whois
from urllib.parse import urlparse
from datetime import datetime

# Function to validate SSL certificate
def validate_ssl_certificate(url):
    hostname = urlparse(url).hostname
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    return True  # Certificate is valid
    except Exception as e:
        return False  # No certificate or invalid certificate
    return False

# Function to check URLScan.io API
def check_urlscan(url):
    API_KEY = 'YOUR_URLSCAN_API_KEY'  # Replace with your URLScan API key
    API_URL = 'https://urlscan.io/api/v1/scan/'
    headers = {
        'Content-Type': 'application/json',
        'API-Key': API_KEY
    }
    payload = {
        "url": url,
        "public": "on"
    }
    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        if response.status_code == 200:
            return "URLScan.io: Scan submitted successfully"
        else:
            return f"Error submitting URLScan.io scan: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error submitting URLScan.io scan: {e}"

# Function for heuristic analysis
def heuristic_analysis(url):
    suspicious_keywords = ["login", "account", "verify", "update", "digital", "password"]
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            return f"Potential phishing indicator found: '{keyword}'"
    return "No issues found"  # No suspicious keywords found

# Function for domain age check
def check_domain_age(url):
    try:
        domain_info = whois.whois(urlparse(url).hostname)
        creation_date = domain_info.creation_date
        age_result = f"Domain age: {datetime.now() - creation_date if creation_date else 'Unknown'}"
        domain_info_text = (
            f"Domain name: {domain_info.domain_name}\n\n"
            f"Registrar: {domain_info.registrar}\n\n"
            f"Registrar URL: {domain_info.registrar_url}\n\n"
            f"Updated date: {domain_info.updated_date}\n\n"
            f"Creation date: {creation_date}\n\n"
        )
        return age_result, domain_info_text
    except Exception as e:
        return "Domain age: Unknown", f"Error retrieving domain information: {e}"

# Function to check website safety
def check_website_safety():
    url = entry.get()
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            ssl_result = validate_ssl_certificate(url)
            urlscan_result = check_urlscan(url)
            heuristic_result = heuristic_analysis(url)
            age_result, domain_info_text = check_domain_age(url)
            # Construct the result message
            result = "Website security analysis:\n"
            http_status = 'HTTPS' if url.startswith('https') else 'HTTP'
            result += f"HTTP/HTTPS: {http_status}\n"
            result += f"SSL Certificate: {'Valid' if ssl_result else 'Invalid'}\n"
            result += f"URLScan.io: {urlscan_result}\n"
            result += f"Heuristic Analysis: {heuristic_result}\n"
            result += f"Domain Age: {age_result}\n"
            result_label.config(text=result)
            if domain_info_text:
                display_domain_info(domain_info_text)
            # Determine if the website is secure
            if (http_status == 'HTTPS' and ssl_result and
                heuristic_result == "No issues found" and
                "less than 6 months" not in age_result):
                secure_status_label.config(text="Website is Secure", fg="green", font=("Helvetica", 20, "bold"))
            else:
                secure_status_label.config(text="Website is Not Secure", fg="red", font=("Helvetica", 20, "bold"))
        else:
            result_label.config(text="Website may not be secure.")
            secure_status_label.config(text="Website is Not Secure", fg="red", font=("Helvetica", 20, "bold"))
    except requests.exceptions.RequestException as e:
        result_label.config(text="Error: Unable to access website.")
        secure_status_label.config(text="Website is Not Secure", fg="red", font=("Helvetica", 20, "bold"))

# Function to display domain information
def display_domain_info(domain_info_text):
    domain_info_label.config(text=domain_info_text)

# Create GUI
root = tk.Tk()
root.title("Website Security Checker")

# Create a tabbed notebook
notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill='both')

# Create the main tab
main_frame = ttk.Frame(notebook)
notebook.add(main_frame, text="Main")
label = tk.Label(main_frame, text="Enter website URL:", font=("Helvetica", 16))
label.pack(pady=10)
entry = tk.Entry(main_frame, width=50, font=("Helvetica", 16))
entry.pack(pady=10)
safety_button = tk.Button(main_frame, text="Check Website Safety", command=check_website_safety, font=("Helvetica", 16))
safety_button.pack(pady=10)
secure_status_label = tk.Label(main_frame, text="", font=("Helvetica", 20))
secure_status_label.pack(pady=10)
result_label = tk.Label(main_frame, text="", font=("Helvetica", 12))
result_label.pack(pady=10)

# Create the domain info tab
domain_info_frame = ttk.Frame(notebook)
notebook.add(domain_info_frame, text="Domain Info")
domain_info_label = tk.Label(domain_info_frame, text="", font=("Helvetica", 10), justify="left", anchor="w")
domain_info_label.pack(pady=10, padx=10)

root.mainloop()