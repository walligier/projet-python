import feedparser
import requests
import re
import pandas as pd
from email.mime.text import MIMEText
import matplotlib.pyplot as plt

##ETAPE 1
url1 = "https://www.cert.ssi.gouv.fr/avis/feed"
url2 = "https://www.cert.ssi.gouv.fr/alerte/feed"
rss_feed1 = feedparser.parse(url1)
rss_feed2 = feedparser.parse(url2)
for entry in rss_feed1.entries:
    print('Titre:', entry.title)
    print('Description:', entry.description)
    print('Lien:', entry.link)
    print('Date:', entry.published)
for entry in rss_feed2.entries:
    print('Titre:', entry.title)
    print('Description:', entry.description)
    print('Lien:', entry.link)
    print('Date:', entry.published)
# %%
##ETAPE 2
url = "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-001/json/"
response = requests.get(url)
data = response.json()
ref_cves = list(data["cves"])  # Extraction des CVE reference dans la clé cves du dict data
# attention il s’agit d’une liste des dictionnaires avec name et url comme clés
print("CVE référencés ", ref_cves)
# Extraction des CVE avec une regex
cve_pattern = r"CVE-\d{4}-\d{4,7}"
cve_list = list(set(re.findall(cve_pattern, str(data))))
print("CVE trouvés :", cve_list)

# %%
##ETAPE 3
cve_id = "CVE-2023-24488"
url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
response = requests.get(url)
data = response.json()
# Extraire la description
description = data["containers"]["cna"]["descriptions"][0]["value"]  # Extraire le score CVSS
# ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,
# ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé
cvss_score = data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
cwe = "Non disponible"
cwe_desc = "Non disponible"
problemtype = data["containers"]["cna"].get("problemTypes", {})
if problemtype and "descriptions" in problemtype[0]:
    cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
    cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")
# Extraire les produits affectés
affected = data["containers"]["cna"]["affected"]
for product in affected:
    vendor = product["vendor"]
    product_name = product["product"]
    versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
    print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")
# Afficher les résultats
print(f"CVE : {cve_id}")
print(f"Description : {description}")
print(f"Score CVSS : {cvss_score}")
print(f"Type CWE : {cwe}")
print(f"CWE Description : {cwe_desc}")

cve_id = "CVE-2023-46805"
url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
response = requests.get(url)
data = response.json()
# Extraire le score EPSS
epss_data = data.get("data", [])
if epss_data:
    epss_score = epss_data[0]["epss"]
    print(f"CVE : {cve_id}")
    print(f"Score EPSS : {epss_score}")
else:
    print(f"Aucun score EPSS trouvé pour {cve_id}")

# %%
##ETAPE4
rssfeed = rss_feed1 + rss_feed2
all_entries = rssfeed.entries
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


# %%
##ETAPE 5
# Histogramme des scores CVSS

# Classement des produits ou éditeurs les plus affectés

# Nuage de points entre Score CVSS et Score EPSS


# %%
##ETAPE 6
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
