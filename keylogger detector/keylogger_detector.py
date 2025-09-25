# keylogger_detector.py

import psutil
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext
from datetime import datetime
import os

# --- Core Detection Logic (Functions) ---
def find_keylogger_processes(suspicious_names):
    """
    Scans the system for running processes with names that are
    known to be associated with keyloggers.
    """
    found_processes = []
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'].lower() in suspicious_names:
                found_processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return found_processes

def find_suspicious_connections():
    """
    Scans the system for processes with active network connections,
    ignoring connections to known, trusted services.
    """
    suspicious_connections = {}
    # A list of trusted IP addresses to ignore.
    # This list can be expanded to include more common, legitimate services.
    trusted_ips = [
        "127.0.0.1",  # localhost
        "0.0.0.0",    # All local addresses
        "255.255.255.255" # Broadcast address
    ]
    
    for proc in psutil.process_iter(['name']):
        try:
            connections = proc.connections()
            if connections:
                # Check each connection for the process
                for conn in connections:
                    # Check if the connection has a remote address and is not a loopback
                    if conn.raddr and conn.raddr.ip not in trusted_ips:
                        # If the connection is to an unknown remote IP,
                        # flag the process as suspicious.
                        if proc.pid not in suspicious_connections:
                            suspicious_connections[proc.pid] = {
                                'name': proc.info['name'],
                                'connections': [conn]
                            }
                        else:
                            suspicious_connections[proc.pid]['connections'].append(conn)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return suspicious_connections

# --- New function to check for unusual behavior ---
def find_unusual_processes():
    """
    Scans the system for processes running from unusual or suspicious
    file paths, which could indicate a hidden threat.
    """
    unusual_processes = []
    # List of common suspicious directories where malware often hides.
    # Note: These paths are examples for Windows systems.
    suspicious_paths = [
        os.path.join(os.environ['APPDATA']),
        os.path.join(os.environ['LOCALAPPDATA']),
        os.path.join(os.environ['TEMP'])
    ]

    for proc in psutil.process_iter(['name', 'exe']):
        try:
            # Check if the process executable path is in a suspicious directory
            if proc.info['exe'] and any(path in proc.info['exe'] for path in suspicious_paths):
                unusual_processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
            continue
    return unusual_processes

# --- New Function to Save Report ---
def save_report_to_file(report_content):
    """
    Saves the scan report to a text file with a timestamped filename.
    """
    # Create the 'reports' directory if it doesn't exist
    if not os.path.exists("reports"):
        os.makedirs("reports")

    # Generate a unique filename with a timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reports/keylogger_report_{timestamp}.txt"
    
    try:
        with open(filename, "w") as f:
            f.write(report_content)
        messagebox.showinfo("Report Saved", f"Scan report saved to:\n{filename}")
    except IOError as e:
        messagebox.showerror("Error", f"Failed to save report: {e}")

# --- GUI Logic (Updated) ---
def run_scan():
    """
    Function to perform the scan and update the GUI's text area.
    """
    # Clear previous results from the text area
    report_text_area.delete('1.0', tk.END)
    report_text_area.insert(tk.END, "Scanning... Please wait.\n\n")
    
    # Update the GUI to show a "scanning" state
    status_label.config(text="Scanning in progress...", fg="blue")
    
    # Run all core detection logic
    found_by_name = find_keylogger_processes(suspicious_process_names)
    found_by_connection = find_suspicious_connections()
    found_by_behavior = find_unusual_processes() # New call

    # Create the report string
    report = ""
    if found_by_name or found_by_connection or found_by_behavior:
        status_label.config(text="Threats Detected!", fg="red")
        report += "ALERT: Possible threats detected!\n\n"
        if found_by_name:
            report += "Processes with suspicious names:\n"
            for proc in found_by_name:
                report += f"  - Name: {proc.info['name']} (PID: {proc.pid})\n"
        
        if found_by_connection:
            if found_by_name:
                report += "\n"
            report += "Processes with active network connections:\n"
            for pid, data in found_by_connection.items():
                report += f"  - Name: {data['name']} (PID: {pid})\n"
                for conn in data['connections']:
                    report += f"    - Connection to: {conn.raddr.ip}:{conn.raddr.port}\n"
        
        if found_by_behavior:
            if found_by_name or found_by_connection:
                report += "\n"
            report += "Processes with unusual file paths:\n"
            for proc in found_by_behavior:
                report += f"  - Name: {proc.info['name']} (PID: {proc.pid})\n"
                report += f"    - Path: {proc.info['exe']}\n"
        
    else:
        status_label.config(text="System Clean", fg="green")
        report = "No known threats detected. Your system appears clean."
    
    # Insert the final report into the text area
    report_text_area.insert(tk.END, report)
    
    # Save the report if the checkbox is checked
    if save_var.get():
        save_report_to_file(report)

def main():
    """
    Sets up the main GUI window.
    """
    global status_label, report_text_area, suspicious_process_names, save_var

    # Define a list of suspicious process names.
    suspicious_process_names = [
        "pykeylogger.exe",
        "keylog.exe",
        "logkeys.exe",
        "keyboard_monitor.exe",
        "winlogger.exe"
    ]

    # Create the main application window
    root = tk.Tk()
    root.title("Keylogger Detector")
    root.geometry("600x450")
    root.configure(bg="#e0e0e0")

    # Main frame with modern padding and background
    main_frame = tk.Frame(root, padx=20, pady=20, bg="#e0e0e0")
    main_frame.pack(fill=tk.BOTH, expand=True)

    # Title label
    title_label = tk.Label(main_frame, text="Keylogger Detection Tool", font=("Helvetica", 18, "bold"), bg="#e0e0e0", fg="#333")
    title_label.pack(pady=(0, 15))

    # Status label
    status_label = tk.Label(main_frame, text="Click 'Run Scan' to start.", font=("Helvetica", 14), bg="#e0e0e0", fg="#555")
    status_label.pack(pady=(0, 10))

    # Scrolled Text area for report output
    report_text_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, height=15, font=("Courier New", 10), bg="#ffffff", fg="#333", relief=tk.FLAT, borderwidth=2)
    report_text_area.pack(fill=tk.BOTH, expand=True, pady=10)

    # Options frame for buttons and checkbox
    options_frame = tk.Frame(main_frame, bg="#e0e0e0")
    options_frame.pack(fill=tk.X, pady=10)

    # Checkbox to choose whether to save the report
    save_var = tk.BooleanVar()
    save_checkbox = tk.Checkbutton(options_frame, text="Save report to file", variable=save_var, font=("Helvetica", 10), bg="#e0e0e0")
    save_checkbox.pack(side=tk.LEFT, padx=(0, 20))

    # Button to run the scan
    scan_button = tk.Button(options_frame, text="Run Scan", command=run_scan, font=("Helvetica", 12, "bold"), bg="#2196F3", fg="white", activebackground="#1976D2", relief="raised", padx=10, pady=5)
    scan_button.pack(side=tk.RIGHT)
    
    # Start the Tkinter event loop
    root.mainloop()

if __name__ == "__main__":
    main()
