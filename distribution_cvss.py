import pandas as pd
import matplotlib.pyplot as plt

# Lire le fichier CSV
df = pd.read_csv('resultats_cve_nettoye.csv', encoding='utf-8')

# Fonction pour classer les scores CVSS
def categorize_cvss(cvss_score):
    try:
        score = float(cvss_score)
        if score >= 9.0:
            return 'Critique'
        elif score >= 7.0:
            return 'Élevée'
        elif score >= 4.0:
            return 'Moyenne'
        else:
            return 'Faible'
    except ValueError:
        return 'Non disponible'

# Appliquer la fonction pour catégoriser les CVSS
df['Gravité CVSS'] = df['CVSS Score'].apply(categorize_cvss)

# Filtrer les lignes où le score CVSS est disponible (non vide ou non 'Non disponible')
df_valid_cvss = df[df['CVSS Score'].notna() & (df['CVSS Score'] != 'Non disponible')]

# Créer l'histogramme de distribution des scores CVSS
plt.figure(figsize=(8, 6))
plt.hist(df_valid_cvss['Gravité CVSS'], bins=4, edgecolor='black', alpha=0.7)

# Ajouter des labels et un titre
plt.title('Distribution des vulnérabilités selon la gravité CVSS')
plt.xlabel('Niveau de gravité')
plt.ylabel('Nombre de vulnérabilités')

# Afficher les résultats
plt.show()
