import feedparser
import requests
import re
import pandas as pd
from email.mime.text import MIMEText
import smtplib
from datetime import datetime, timedelta, timezone


## ETAPE 1 - Extraction des flux RSS
url_avis = "https://www.cert.ssi.gouv.fr/avis/feed"
url_alerte = "https://www.cert.ssi.gouv.fr/alerte/feed"

# Fonction pour traiter les flux RSS
def process_rss_feed(url):
    response = requests.get(url)
    if response.status_code == 200:
        rss_feed = feedparser.parse(response.content)
        entries = []
        for entry in rss_feed.entries:
            print("Titre :", entry.title)
            print("Description:", entry.description)
            print("Lien :", entry.link)
            print("Date :", entry.published)
            print("----------------------------------------------------------")
            entries.append({
                'title': entry.title,
                'link': entry.link,
                'date': entry.published,
                'type': 'Alerte' if 'alerte' in url else 'Avis'
            })
        return entries
    else:
        print("Erreur lors du téléchargement du flux RSS.")
        return []

# Filtrer les entrées en fonction de la date de publication
def filter_by_date(entries, days=30):
    threshold_date = datetime.now(timezone.utc) - timedelta(days=days)  # Utilisation de timezone.utc
    filtered_entries = [
        entry for entry in entries
        if datetime.strptime(entry['date'], "%a, %d %b %Y %H:%M:%S %z") > threshold_date
    ]
    return filtered_entries

avis_entries = process_rss_feed(url_avis)
alerte_entries = process_rss_feed(url_alerte)
all_entries = avis_entries + alerte_entries
all_entries = filter_by_date(all_entries, days=30)  # Filtrer pour les 30 derniers jours

# Fonction pour extraire les CVE depuis une URL
cve_pattern = r"CVE-\d{4}-\d{4,7}"
def extract_cves(url, max_cves=5):
    response = requests.get(url + "/json/")
    if response.status_code == 200:
        data = response.json()
        # Extraction des CVE
        ref_cves = [cve["name"] for cve in data.get("cves", [])]
        cve_list = list(set(re.findall(cve_pattern, str(data))))
        return ref_cves[:max_cves] + cve_list[:max_cves]
    return []

## ETAPE 2 - Extraction des CVE depuis toutes les alertes
for entry in all_entries:
    entry['cves'] = extract_cves(entry['link'])

## ETAPE 3 - Enrichissement des CVE
def enrich_cve(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        # Extraire la description
        try:
            description = data["containers"]["cna"]["descriptions"][0]["value"]
        except KeyError:
            description = "Non disponible"

        # Extraire le score CVSS
        try:
            cvss_score = data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
            severity = data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseSeverity"]
        except KeyError:
            cvss_score = "Non disponible"
            severity = "Non disponible"

        # Extraire les informations CWE
        cwe = "Non disponible"
        cwe_desc = "Non disponible"
        problemtype = data["containers"]["cna"].get("problemTypes", {})
        if problemtype and "descriptions" in problemtype[0]:
            cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")

        # Extraire les produits affectés
        affected_info = []
        try:
            affected = data["containers"]["cna"]["affected"]
            for product in affected:
                vendor = product["vendor"]
                product_name = product["product"]
                versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
                affected_info.append({
                    'vendor': vendor,
                    'product': product_name,
                    'versions': ', '.join(versions)
                })
        except KeyError:
            affected_info = [{
                'vendor': 'Non disponible',
                'product': 'Non disponible',
                'versions': 'Non disponible'
            }]

        # Extraire le score EPSS
        epss_score = "Non disponible"
        epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        epss_response = requests.get(epss_url)
        if epss_response.status_code == 200:
            epss_data = epss_response.json().get("data", [])
            if epss_data:
                epss_score = epss_data[0].get("epss", "Non disponible")

        enriched_data = {
            'cve_id': cve_id,
            'description': description,
            'cvss_score': cvss_score,
            'severity': severity,
            'cwe': cwe,
            'cwe_desc': cwe_desc,
            'epss_score': epss_score,
            'affected': affected_info
        }

        print(enriched_data)
        return enriched_data
    return {}

# Enrichissement pour chaque CVE et compilation des résultats
data_rows = []
for entry in all_entries:
    for cve in entry['cves']:
        enriched = enrich_cve(cve)
        if enriched:
            for affected in enriched.get('affected', []):
                data_rows.append([
                    entry['title'], entry['type'], entry['date'], cve,
                    enriched['cvss_score'], enriched['severity'],
                    enriched['cwe'], enriched['epss_score'], entry['link'],
                    enriched['description'], affected['vendor'],
                    affected['product'], affected['versions']
                ])

# Création du DataFrame final
df = pd.DataFrame(data_rows, columns=[
    'Titre', 'Type', 'Date', 'CVE', 'CVSS Score', 'Base Severity',
    'Type CWE', 'EPSS Score', 'Lien', 'Description', 'Éditeur',
    'Produit', 'Versions Affectées'
])

print(df)

# Exporter vers un fichier CSV
df.to_csv('resultats_cve.csv', index=False, encoding='utf-8')
print("Le fichier CSV a été exporté avec succès : resultats_cve.csv")

## ETAPE 5 et 6 - Envoi d'email
def send_email(to_email, subject, body):
    from_email = "VOTRE MAIL"
    password = "VOTRE CLE D'ACCES DU MAIL"

    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()

print("Traitement terminé")
