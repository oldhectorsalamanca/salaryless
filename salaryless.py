from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import json
import os
import requests
import time

# List of categories to consider when grouping detected technologies
WAPPALYZER_CATEGORIES = {
    "JavaScript frameworks", "Miscellaneous", "Web servers", "Programming languages", "Operating systems",
    "Web server extensions", "JavaScript libraries", "Analytics", "Advertising", "Content Management Systems",
    "Ecommerce", "Hosting Providers", "Databases", "CDN", "Email", "Mobile", "Security", "SSL Certificates",
    "Infrastructure", "Video", "Social Networks", "Font Script", "Dev Tools", "Programming Frameworks",
    "CMS", "Widgets", "Photo galleries", "Blogs", "Video players", "Tag managers", "SEO", "Reverse proxies",
    "UI frameworks", "WordPress themes", "WordPress plugins", "Performance"
}

def read_properties(path):
    """
    Read key-value pairs from a .properties file, ignoring comments and empty lines.
    """
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
    Use Selenium to open Wappalyzer lookup page and scrape detected technologies.
    """
    props = read_properties("properties")
    profile_path = os.path.expanduser(props.get("firefox_profile_path", ""))

    if not profile_path or not os.path.exists(profile_path):
        raise ValueError(f"Invalid or missing profile path: {profile_path}")

    options = Options()
    options.headless = False  # Set to True to run headless
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


def group_by_category(tech_list):
    """
    Organize list of technologies into categories.
    If a technology doesn’t match any known category, it goes into 'Miscellaneous'.
    """
    services = {"Miscellaneous": []}
    for tech in tech_list:
        name = tech["name"]
        version = tech["version"]
        placed = False
        for category in WAPPALYZER_CATEGORIES:
            if category.lower() in name.lower():
                services.setdefault(category, []).append({"name": name, "version": version})
                placed = True
                break
        if not placed:
            services["Miscellaneous"].append({"name": name, "version": version})
    return services


def print_services(services):
    """
    Print technologies by category, and count how many have versions.
    Returns total count of items with detected versions.
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
    Query NVD API for CVEs matching each technology name+version.
    Returns dictionary of 'Name Version' to list of CVE details.
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
    Print found CVEs for each technology version.
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
    url = input("Enter the URL to analyze with Wappalyzer: ").strip()
    clean_domain = url.replace(".", "")
    print("Detecting technologies from Wappalyzer...\n")

    raw_tech = detect_wappalyzer_technologies(url)
    services = group_by_category(raw_tech)
    version_count = print_services(services)

    os.makedirs("versions_CVEs", exist_ok=True)
    with open(f"versions_CVEs/services_{clean_domain}.json", "w", encoding="utf-8") as f:
        json.dump(services, f, indent=2, ensure_ascii=False)
    print(f"Services saved to 'services_{clean_domain}.json'\n")

    if version_count == 0:
        print("No versions found. Skipping CVE search.")
        return

    answer = input("Do you want to search for CVEs for these versions? (y/n): ").strip().lower()
    if answer != "y":
        print("CVE search skipped.")
        return

    print("Searching for CVEs...")
    cves = search_cves(services)
    print_cves(cves)

    with open(f"versions_CVEs/cves_{clean_domain}.json", "w", encoding="utf-8") as f:
        json.dump(cves, f, indent=2, ensure_ascii=False)
    print(f"CVEs saved to 'cves_{clean_domain}.json'")

if __name__ == "__main__":
    main()
