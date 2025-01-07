import pandas as pd
import matplotlib.pyplot as plt
import re

# Lire le fichier CSV
df = pd.read_csv('resultats_cve.csv', encoding='utf-8')

# Supposons que la colonne 'Type CWE' contient les informations sur les types de vulnérabilités
# Extraction des types de vulnérabilités CWE (par exemple, 'CWE-89' devient 'Injection SQL')

cwe_dict = {
    'CWE-89': 'Injection SQL',
    'CWE-79': 'Cross-site Scripting (XSS)',
    'CWE-119': 'Débordement de tampon',
    'CWE-20': 'Contrôle d’accès inadéquat',
    'CWE-287': 'Authentification contournée',
    # Ajoutez d'autres CWE selon votre besoin...
}

# Fonction pour extraire et mapper les codes CWE
def map_cwe_to_description(cwe_code):
    if pd.notna(cwe_code):
        cwe_list = re.findall(r'CWE-\d+', str(cwe_code))  # Chercher toutes les occurrences de CWE
        descriptions = [cwe_dict.get(cwe, 'Autre') for cwe in cwe_list]  # Mapper selon le dictionnaire
        return ', '.join(descriptions)
    return 'Non spécifié'

# Appliquer la fonction pour extraire les descriptions des vulnérabilités dans une nouvelle colonne 'CWE_Description'
df['CWE_Description'] = df['Type CWE'].apply(map_cwe_to_description)

# Comptage des occurrences de chaque type de vulnérabilité (CWE)
cwe_counts = df['CWE_Description'].value_counts()

# Regrouper les vulnérabilités peu fréquentes sous 'Autres'
threshold = 5  # Seuil pour regrouper les catégories peu fréquentes
cwe_counts = cwe_counts.apply(lambda x: 'Autres' if x < threshold else x)

# Recompter les occurrences après regroupement
cwe_counts = cwe_counts.groupby(cwe_counts).sum()

# Créer le diagramme circulaire
plt.figure(figsize=(8, 8))
plt.pie(cwe_counts, labels=cwe_counts.index, autopct='%1.1f%%', startangle=90, colors=plt.cm.Paired.colors)
plt.title('Répartition des types de vulnérabilités (CWE)')
plt.axis('equal')  # Pour avoir un cercle parfait

# Afficher le diagramme
plt.show()
