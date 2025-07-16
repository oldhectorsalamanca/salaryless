# Technology Detection and CVE Search Tool

## Description

**Salaryless** uses Selenium to extract the technologies from a given URL using **Wappalyzer**,  
then searches for **CVE vulnerabilities** related to the detected versions using the **NVD API**.

---

## Requirements

- Python 3.8 or higher  
- Firefox installed  
- GeckoDriver installed and added to `PATH`  
  [GeckoDriver Releases](https://github.com/mozilla/geckodriver/releases)  
- A configured Firefox profile to maintain session (optional but recommended)  
- A `properties` file with the path to the Firefox profile where Wappalyzer is logged in

---

## Installation

1. Clone or download this repository.

2. (Optional but recommended) Create a virtual environment:
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
   
# Install the dependencies:
pip install -r requirements.txt

Add the following line to the properties file in the project directory:
firefox_profile_path=/partial/path/to/firefox/profile

Example on Linux:
firefox_profile_path=/home/user/.mozilla/firefox/abcd1234.default-release

## Usage
Run the main script:
python salaryless.py
The program will ask for a URL, detect the technologies used on that website, and search for known CVEs associated with the versions found.

## Notes
Make sure Firefox and GeckoDriver are correctly installed and compatible.

To preserve sessions or login data, use a dedicated Firefox profile and configure its path in the properties file.

If you get errors related to disk space or /tmp being full, free up space with:
sudo rm -rf /tmp/*

## Contact
For questions or issues, dont contact me!
