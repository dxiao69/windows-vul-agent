# pip install psutil winreg requests hashlib
# Step 1: Import Libraries
import os
import psutil
import hashlib
import subprocess
import json
import requests
from winreg import OpenKey, HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, EnumValue

# CVE Database URL (example: NVD API or local vulnerability database)
CVE_API = "https://services.nvd.nist.gov/rest/json/cves/1.0"

# Step 2: System Snapshot (Files, Processes, Registry)
def generate_file_hash(file_path):
    try:
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as file:
            buffer = file.read()
            hasher.update(buffer)
        return hasher.hexdigest()
    except Exception as e:
        return str(e)

def list_files(directory):
    file_info = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = generate_file_hash(file_path)
            file_info[file_path] = file_hash
    return file_info

def list_processes():
    return {p.pid: p.name() for p in psutil.process_iter(['pid', 'name'])}

def list_registry_keys(root_key):
    registry_info = {}
    try:
        with OpenKey(root_key, "") as key:
            i = 0
            while True:
                try:
                    name, value, _ = EnumValue(key, i)
                    registry_info[name] = value
                    i += 1
                except OSError:
                    break
    except Exception:
        pass
    return registry_info

def system_snapshot():
    return {
        "files": list_files("C:\\"),  # Adjust the directory as needed
        "processes": list_processes(),
        "registry": list_registry_keys(HKEY_LOCAL_MACHINE)
    }

# Step 3: Compare Snapshots
def compare_snapshots(before, after):
    changes = {
        "new_files": [],
        "modified_files": [],
        "new_processes": [],
        "new_registry_keys": []
    }

    # Compare Files
    for file, hash in after['files'].items():
        if file not in before['files']:
            changes['new_files'].append(file)
        elif before['files'][file] != hash:
            changes['modified_files'].append(file)

    # Compare Processes
    for pid, name in after['processes'].items():
        if pid not in before['processes']:
            changes['new_processes'].append(name)

    # Compare Registry
    for key, value in after['registry'].items():
        if key not in before['registry']:
            changes['new_registry_keys'].append(f"{key}: {value}")

    return changes

# Step 4: Check Vulnerabilities via CVE API
def check_vulnerability(app_name, version):
    try:
        response = requests.get(f"{CVE_API}?keyword={app_name} {version}")
        cves = response.json().get("result", {}).get("CVE_Items", [])
        vulnerabilities = []

        for cve in cves:
            vuln_info = {
                "id": cve['cve']['CVE_data_meta']['ID'],
                "description": cve['cve']['description']['description_data'][0]['value'],
                "severity": cve.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", "Unknown")
            }
            vulnerabilities.append(vuln_info)
        return vulnerabilities
    except Exception as e:
        return [{"error": str(e)}]

# Step 5: Generate Report
def generate_report(changes, vulnerabilities):
    report = {
        "changes": changes,
        "vulnerabilities": vulnerabilities
    }
    with open("vulnerability_report.json", "w") as file:
        json.dump(report, file, indent=4)
    print("Vulnerability report generated: vulnerability_report.json")

# Main Function
if __name__ == "__main__":
    print("Taking pre-installation snapshot...")
    before_snapshot = system_snapshot()

    input("Install the application and press Enter to continue...")

    print("Taking post-installation snapshot...")
    after_snapshot = system_snapshot()

    print("Comparing snapshots...")
    changes = compare_snapshots(before_snapshot, after_snapshot)

    print("Checking for vulnerabilities...")
    app_name = input("Enter application name: ")
    version = input("Enter application version: ")
    vulnerabilities = check_vulnerability(app_name, version)

    print("Generating report...")
    generate_report(changes, vulnerabilities)


output_exmaple ={
    "changes": {
        "new_files": ["C:\\Program Files\\NewApp\\app.exe"],
        "modified_files": ["C:\\Windows\\System32\\dllhost.exe"],
        "new_processes": ["NewApp.exe"],
        "new_registry_keys": ["Software\\NewApp: Installed"]
    },
    "vulnerabilities": [
        {
            "id": "CVE-2023-12345",
            "description": "Remote code execution vulnerability",
            "severity": "Critical"
        }
    ]
}
