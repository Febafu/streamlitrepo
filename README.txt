======================================================================
THREATSCOPE OBSERVATORY: PHISHING URL INTELLIGENCE
Academy Project - Phishing URL Analysis
======================================================================

1. PROJECT OVERVIEW
-------------------
ThreatScope Observatory is a Python-based security tool designed to 
collect and analyze live malicious URL data. It identifies patterns 
in phishing infrastructure, such as top-level domain (TLD) usage, 
malware family distribution, and URL survival rates.

2. KEY FEATURES
---------------
* DATA INGESTION: Aggregates data from URLhaus and ThreatFox feeds.
* RESILIENT PIPELINE: Features a fallback system to handle network 
  restrictions (CSV -> JSON -> Synthetic Data).
* ANALYTICS ENGINE: Processes 20,000+ records to find infrastructure 
  trends and temporal bursts.
* DASHBOARD: Includes an interactive Streamlit interface with 
  six tabbed analysis panels (Extra Credit Requirement).

3. RECENT LIVE DATA FINDINGS (2026-03-19)
-----------------------------------------
* Total URLs Analyzed: 20,343
* Active Threats: 1,970 (~9.7% of the dataset)
* Primary TLDs: .com, .top, and .xyz dominate the landscape.
* Top Malware: Emotet and Agent Tesla remain the most frequent tags.

4. FILE STRUCTURE
-----------------
* phishing_analysis.py  : Main engine for data collection/analysis.
* streamlit_app.py      : Code for the web-based dashboard.
* requirements.txt      : List of Python libraries needed to run.
* readme.txt            : This documentation file.
* Phishing_Report.pdf   : Formal methodology and full analysis.

5. INSTALLATION AND USAGE
-------------------------
A. Install Dependencies:
   pip install -r requirements.txt

B. Run the Analysis:
   python phishing_analysis.py

C. Launch the Dashboard:
   streamlit run streamlit_app.py

6. TECHNICAL FIXES IMPLEMENTED
------------------------------
* UNICODE FIX: All file writes use UTF-8 encoding to prevent crashes 
  on Windows/Notepad systems.
* API PATCH: Fixed 401 Unauthorized errors for school firewalls.
* VERSION FIX: Updated Streamlit and Altair requirements to resolve 
  ModuleNotFound errors in the cloud environment.

7. SAFETY AND ETHICS
--------------------
WARNING: All data points represent live malicious infrastructure. 
This tool performs metadata analysis only. DO NOT visit or resolve 
any URLs contained within the output files. No personal data was 
collected during this research.

======================================================================
End of README.txt
======================================================================