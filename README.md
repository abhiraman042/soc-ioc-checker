# SOC IOC Checker 🔎
### SOC Dashboard Preview

![SOC IOC Checker Dashboard](screenshots/soc-dashboard.png)
A Python-based Security Operations Center (SOC) automation project that checks Indicators of Compromise (IOCs) using the VirusTotal API and generates an Excel report for security analysis.

## 🚀 Features

- Checks IP addresses, domain names, and file hashes.
- Retrieves threat intelligence from VirusTotal.
- Displays malicious, suspicious, and harmless detection counts.
- Classifies indicators with a simple verdict: Malicious, Suspicious, Clean, or Unknown.
- Exports results to CSV and Excel.
- Creates an Excel SOC dashboard with a summary and pie chart.

## 🛠️ Technologies Used

- Python
- VirusTotal API v3
- Requests
- OpenPyXL
- Excel reporting

## 📁 Project Structure

```text
soc-ioc-checker/
├── ioc_checker.py
├── iocs.txt
├── requirements.txt
└── .gitignore
```

## ⚙️ Setup and Usage

### 1. Clone the repository

```bash
git clone https://github.com/abhiraman042/soc-ioc-checker.git
cd soc-ioc-checker
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure your VirusTotal API key

Set your API key as an environment variable.

**Windows PowerShell:**

```powershell
$env:VIRUSTOTAL_API_KEY = Read-Host "Enter VirusTotal API key"
```

Keep your API key private. Never hardcode it or upload it to GitHub.

### 4. Add indicators

Add IP addresses, domains, or file hashes to `iocs.txt`, one per line.

### 5. Run the checker

```bash
python ioc_checker.py
```

Follow any prompts shown by the script.

## 📊 Output

The project generates reports containing:

- Indicator details
- Malicious, suspicious, and harmless detection counts
- Overall verdicts
- An Excel dashboard with a summary chart

Generated reports are excluded from Git tracking through `.gitignore`.

## 🎯 Learning Objectives

- Practiced using threat intelligence APIs.
- Automated basic IOC enrichment with Python.
- Worked with API responses and detection statistics.
- Generated structured reports for SOC investigations.
- Explored automation opportunities for security operations.

## ⚠️ Disclaimer

This project is intended for educational and defensive security purposes. A `Clean` verdict does not guarantee that an indicator is safe; it means the available VirusTotal results did not show malicious or suspicious detections under this project's classification logic.

## 👨‍💻 Author

**Abhiraman R**

GitHub: [@abhiraman042](https://github.com/abhiraman042)
