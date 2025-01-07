print("coucou")

import feedparser
import requests
import re
import pandas as pd
from email.mime.text import MIMEText

##ETAPE 1
url_avis = "https://www.cert.ssi.gouv.fr/avis/feed"
response_avis = requests.get(url_avis)

url_alerte = "https://www.cert.ssi.gouv.fr/alerte/feed"
response_alerte = requests.get(url_alerte)

# Etape 1 :  Extraction des flux RSS

# Vérifie le statut HTTP pour t'assurer que la requête a réussi
if response_avis.status_code == 200:
    rss_feed_avis = feedparser.parse(response_avis.content)
    for entry in rss_feed_avis.entries:
        print("Titre :", entry.title)
        print("Description:", entry.description)
        print("Lien :", entry.link)
        print("Date :", entry.published)
        print("----------------------------------------------------------")
else:
    print("Erreur lors du téléchargement du flux RSS.")

print("----------------------------------------------------------")
print("----------------------------------------------------------")

if response_alerte.status_code == 200:
    rss_feed_alerte = feedparser.parse(response_alerte.content)
    for entry in rss_feed_alerte.entries:
        print("Titre :", entry.title)
        print("Description:", entry.description)
        print("Lien :", entry.link)
        print("Date :", entry.published)
        print("----------------------------------------------------------")
else:
    print("Erreur lors du téléchargement du flux RSS.")

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


##ETAPE4

##ETAPE 5
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