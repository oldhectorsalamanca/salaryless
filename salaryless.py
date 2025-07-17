import sys
import re
import json
import os
import requests
import time
import fileinput
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Known categories to match against or dynamically extract from manual input
DEFAULT_CATEGORIES = {
    "JavaScript frameworks", "Miscellaneous", "Web servers", "Programming languages", "Operating systems",
    "Web server extensions", "JavaScript libraries", "Analytics", "Advertising", "Content Management Systems",
    "Ecommerce", "Hosting Providers", "Databases", "CDN", "Email", "Mobile", "Security", "SSL Certificates",
    "Infrastructure", "Video", "Social Networks", "Font scripts", "Dev Tools", "Programming Frameworks",
    "CMS", "Widgets", "Photo galleries", "Blogs", "Video players", "Tag managers", "SEO", "Reverse proxies",
    "UI frameworks", "WordPress themes", "WordPress plugins", "Performance", "Form builders", "Page builder",
    "JavaScript graphics", "Cookie compliance"
}

def read_properties(path):
    props = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                props[key.strip()] = value.strip()
    return props

def detect_wappalyzer_technologies(target_url):
    """
    Use Selenium to scrape technologies detected by Wappalyzer.
    """
    props = read_properties("properties")
    profile_path = os.path.expanduser(props.get("firefox_profile_path", ""))

    if not profile_path or not os.path.exists(profile_path):
        raise ValueError(f"Invalid or missing profile path: {profile_path}")

    options = Options()
    options.headless = False
    options.set_preference("profile", profile_path)
    options.profile = profile_path

    driver = webdriver.Firefox(options=options)

    try:
        driver.get(f"https://www.wappalyzer.com/lookup/{target_url.strip()}/")
        wait = WebDriverWait(driver, 120)
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR,"small.text--disabled.ml-1")))
        time.sleep(0)

        results = []
        container = driver.find_element(By.CSS_SELECTOR, "div.col-sm-6.col-12")
        cards = container.find_elements(By.CSS_SELECTOR, "div.mb-4.v-card.v-sheet.theme--dark")

        for card in cards:
            tech_items = card.find_elements(By.CSS_SELECTOR,
                "div.v-card__text div.ml-2.d-flex.align-center.text-decoration-none")
            for tech in tech_items:
                try:
                    name = tech.find_element(By.TAG_NAME, "span").text.strip()
                except:
                    name = None
                try:
                    version = tech.find_element(By.CSS_SELECTOR,
                        "small.text--disabled.ml-1").text.strip()
                    version = version.strip("()") if version else None
                except:
                    version = None
                if name:
                    results.append({"name": name, "version": version})
        return results

    finally:
        driver.quit()

def parse_manual_input():
    """
    Parse user-pasted input in Wappalyzer format until EOF (Ctrl+D).
    Each technology is assigned to the last detected category.
    """
    print("Paste technologies (Wappalyzer style). Press Ctrl+D when finished (Ctrl+Z on Windows).\n")
    lines = sys.stdin.read().strip().splitlines()
    services = {}
    current_category = None

    for line in lines:
        line = line.strip()
        if not line:
            continue
        # If the line is a known category, update the current category
        if line in DEFAULT_CATEGORIES:
            current_category = line
            services.setdefault(current_category, [])
        elif current_category:
            # Try to extract version if available
            match = re.match(r"^(.*?)\s+(\d[\d\.a-zA-Z\-]*)$", line)
            if match:
                name = match.group(1).strip()
                version = match.group(2).strip()
                services[current_category].append({"name": name, "version": version})
            else:
                services[current_category].append({"name": line, "version": None})
        else:
            # No category defined yet
            services.setdefault("Miscellaneous", []).append({"name": line, "version": None})
    return services


def normalize_category(name, category_set):
    """
    Match technology name to known category or fallback to Miscellaneous.
    """
    for cat in category_set:
        if cat.lower() in name.lower():
            return cat
    return "Miscellaneous"

def group_by_category(tech_list, category_reference=None):
    """
    Dynamically group technologies by best-matched category.
    """
    if category_reference is None:
        category_reference = DEFAULT_CATEGORIES

    services = {}
    for tech in tech_list:
        name = tech["name"]
        version = tech["version"]
        category = normalize_category(name, category_reference)
        services.setdefault(category, []).append({"name": name, "version": version})

    return services

def flatten_services(services_dict):
    """
    Convert nested dict to flat list of tech items.
    """
    flat = []
    for tech_list in services_dict.values():
        flat.extend(tech_list)
    return flat

def print_services(services):
    """
    Display categorized technologies and count versioned ones.
    """
    total_versions = 0
    for category, tech_list in services.items():
        print(f"{category}:")
        for tech in tech_list:
            version_str = tech["version"] if tech["version"] else "None"
            print(f"  {tech['name']} -> Version {version_str}")
            if tech["version"]:
                total_versions += 1
        print()
    print(f"Found {total_versions} service versions.\n")
    return total_versions

def search_cves(services):
    """
    Query NVD for CVEs matching name+version of each technology.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    found = {}

    for category, tech_list in services.items():
        for tech in tech_list:
            name = tech["name"]
            version = tech["version"]
            if not version:
                continue
            keyword = f"{name} {version}"
            params = {"keywordSearch": keyword, "resultsPerPage": 50}
            try:
                response = requests.get(base_url, params=params)
                response.raise_for_status()
                data = response.json()
                total = data.get("totalResults", 0)
                if total > 0:
                    cve_list = []
                    for item in data.get("vulnerabilities", []):
                        cve_id = item.get("cve", {}).get("id")
                        descs = item.get("cve", {}).get("descriptions", [])
                        desc = next((d.get("value") for d in descs if d.get("lang") == "en"), "")
                        cve_list.append({"cve_id": cve_id, "description": desc})
                    found[keyword] = cve_list
            except Exception as e:
                print(f"Error searching CVEs for {keyword}: {e}")
    return found

def print_cves(cve_dict):
    """
    Print CVEs found for each technology/version.
    """
    if not cve_dict:
        print("No CVEs found.\n")
        return
    print("Found CVEs:")
    for key, cves in cve_dict.items():
        print(f"CVE list for {key}:")
        ids = [cve["cve_id"] for cve in cves]
        print("  " + ", ".join(ids))
        print()

def main():
    if len(sys.argv) < 2:
        print("Usage: python salaryless.py <domain.com>")
        sys.exit(1)

    domain = sys.argv[1].strip()
    clean_domain = domain.replace(".", "")
    manual = input("Do you want to manually input technologies and versions? (y/n): ").strip().lower()

    if manual == 'y':
        services = parse_manual_input()  # Already categorized
    else:
        print("Detecting technologies using Wappalyzer...")
        raw_tech = detect_wappalyzer_technologies(domain)
        services = {"Detected Technologies": raw_tech}

    version_count = print_services(services)

    os.makedirs("versions_CVEs", exist_ok=True)
    with open(f"versions_CVEs/services_{clean_domain}.json", "w", encoding="utf-8") as f:
        json.dump(services, f, indent=2, ensure_ascii=False)
    print(f"Services saved to 'services_{clean_domain}.json'\n")

    if version_count == 0:
        print("No versions found. Skipping CVE search.")
        return

    print("Searching for CVEs...")
    cves = search_cves(services)
    print_cves(cves)

    with open(f"versions_CVEs/cves_{clean_domain}.json", "w", encoding="utf-8") as f:
        json.dump(cves, f, indent=2, ensure_ascii=False)
    print(f"CVEs saved to 'cves_{clean_domain}.json'")

if __name__ == "__main__":
    main()
