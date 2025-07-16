from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import json
import os
import requests
import re
import time

WAPPALYZER_CATEGORIES = {
    "JavaScript frameworks", "Miscellaneous", "Web servers", "Programming languages", "Operating systems",
    "Web server extensions", "JavaScript libraries", "Analytics", "Advertising", "Content Management Systems",
    "Ecommerce", "Hosting Providers", "Databases", "CDN", "Email", "Mobile", "Security", "SSL Certificates",
    "Infrastructure", "Video", "Social Networks", "Font Script", "Dev Tools", "Programming Frameworks",
    "CMS", "Widgets", "Photo galleries", "Blogs", "Video players", "Tag managers", "SEO", "Reverse proxies",
    "UI frameworks", "WordPress themes", "WordPress plugins", "Performance"
}

def leer_propiedades(path):
    propiedades = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                clave, valor = line.split("=", 1)
                propiedades[clave.strip()] = valor.strip()
    return propiedades



def detectar_tecnologias_wappalyzer(url_a_analizar):
    propiedades = leer_propiedades("properties")
    perfil_path = os.path.expanduser(propiedades.get("firefox_profile_path", ""))

    if not perfil_path or not os.path.exists(perfil_path):
        raise ValueError(f"Ruta de perfil inválida o no especificada: {perfil_path}")

    options = Options()
    options.headless = False # CAMBIAR A FALSE SI SE QUIERE VER EL NAVEGADOR, no furula
    options.set_preference("profile", perfil_path)
    options.profile = perfil_path

    driver = webdriver.Firefox(options=options)

    try:
        driver.get(f"https://www.wappalyzer.com/lookup/{url_a_analizar.strip()}/")
        wait = WebDriverWait(driver, 120)
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "div.col-sm-6.col-12")))
        time.sleep(7)

        resultados = []
        contenedor = driver.find_element(By.CSS_SELECTOR, "div.col-sm-6.col-12")
        categorias = contenedor.find_elements(By.CSS_SELECTOR, "div.mb-4.v-card.v-sheet.theme--dark")

        for categoria in categorias:
            techs = categoria.find_elements(By.CSS_SELECTOR, "div.v-card__text div.ml-2.d-flex.align-center.text-decoration-none")
            for tech in techs:
                try:
                    name = tech.find_element(By.TAG_NAME, "span").text.strip()
                except:
                    name = None
                try:
                    version = tech.find_element(By.CSS_SELECTOR, "small.text--disabled.ml-1").text.strip()
                    version = version.strip("()") if version else None
                except:
                    version = None
                if name:
                    resultados.append({"name": name, "version": version})
        return resultados
    finally:
        driver.quit()

def agrupar_por_categoria(lista_tecnologias):
    servicios = {"Miscellaneous": []}  # fallback default
    for tech in lista_tecnologias:
        name = tech["name"]
        version = tech["version"]
        added = False
        for categoria in WAPPALYZER_CATEGORIES:
            if categoria.lower() in name.lower() or categoria.lower() in name.lower().split():
                servicios.setdefault(categoria, []).append({"name": name, "version": version})
                added = True
                break
        if not added:
            servicios["Miscellaneous"].append({"name": name, "version": version})
    return servicios

def imprimir_servicios(servicios):
    total_versions = 0
    for categoria, tech_list in servicios.items():
        print(f"{categoria}:")
        for tech in tech_list:
            version_str = tech["version"] if tech["version"] else "None"
            print(f"{tech['name']} -> Version {version_str}")
            if tech["version"]:
                total_versions += 1
        print()
    print(f"Se han encontrado {total_versions} versiones de servicios.\n")
    return total_versions

def buscar_cves(tecnologias):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    found_cves = {}

    for categoria, tech_list in tecnologias.items():
        for tech in tech_list:
            name = tech["name"]
            version = tech["version"]
            if not version:
                continue

            keyword = f"{name} {version}"
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 50
            }

            try:
                resp = requests.get(base_url, params=params)
                resp.raise_for_status()
                data = resp.json()

                total_results = data.get("totalResults", 0)
                if total_results > 0:
                    cves = []
                    for item in data.get("vulnerabilities", []):
                        cve_id = item.get("cve", {}).get("id")
                        description_data = item.get("cve", {}).get("descriptions", [])
                        description = next((d.get("value") for d in description_data if d.get("lang") == "en"), "")
                        cves.append({"cve_id": cve_id, "description": description})

                    found_cves[f"{name} {version}"] = cves

            except Exception as e:
                print(f"Error buscando CVEs para {keyword}: {e}")

    return found_cves

def imprimir_cves(cves):
    if not cves:
        print("No se encontraron CVEs.\n")
        return
    print("CVEs encontrados:")
    for servicio_version, cve_list in cves.items():
        print(f"Lista de CVEs del {servicio_version}:")
        cve_ids = [cve["cve_id"] for cve in cve_list]
        print(", ".join(cve_ids))
        print()

def main():
    url = input("Introduce la URL que quieres analizar con Wappalyzer: ").strip()
    dominio_limpio = url.replace(".", "")
    print("Obteniendo tecnologías detectadas desde Wappalyzer...\n")
    tecnologias_crudas = detectar_tecnologias_wappalyzer(url)

    servicios = agrupar_por_categoria(tecnologias_crudas)
    total_versions = imprimir_servicios(servicios)

    with open(f"versions_CVEs/servicios_{dominio_limpio}.json", "w", encoding="utf-8") as f:
        json.dump(servicios, f, indent=2, ensure_ascii=False)
    print(f"Servicios guardados en 'servicios_{dominio_limpio}.json'\n")

    if total_versions == 0:
        print("No hay versiones encontradas. No se buscarán CVEs.")
        return

    respuesta = input("¿Quieres buscar CVEs para estas versiones? (s/n): ").strip().lower()
    if respuesta != "s":
        print("No se realizará la búsqueda de CVEs.")
        return

    print("Buscando CVEs...")
    cves = buscar_cves(servicios)
    imprimir_cves(cves)

    with open(f"versions_CVEs/cves_{dominio_limpio}.json", "w", encoding="utf-8") as f:
        json.dump(cves, f, indent=2, ensure_ascii=False)
    print(f"CVEs guardados en 'cves_{dominio_limpio}.json'")

if __name__ == "__main__":
    main()
