import pandas as pd

# Fonction de pré-nettoyage du CSV
def pre_clean_csv(df):
    # Suppression des lignes où la colonne 'Type' est vide ou NaN
    df = df[df['Type'].notna() & (df['Type'].str.strip() != '')]
    
    # Suppression des lignes contenant des valeurs NaN dans des colonnes importantes
    df = df.dropna(subset=['Titre', 'CVE', 'CVSS Score', 'Description'])
    
    # Suppression des doublons basés sur les CVE
    df = df.drop_duplicates(subset=['CVE'])
    
    # Traitement des valeurs vides ou nulles
    df['CVSS Score'].fillna('Non disponible', inplace=True)
    df['Description'].fillna('Non disponible', inplace=True)
    df['Éditeur'].fillna('Non disponible', inplace=True)
    df['Produit'].fillna('Non disponible', inplace=True)
    df['Versions Affectées'].fillna('Non disponible', inplace=True)
    
    # Suppression des espaces inutiles dans les chaînes de caractères
    df['Titre'] = df['Titre'].str.strip()
    df['Description'] = df['Description'].str.strip()

    return df

# Fonction principale de nettoyage
def clean_csv(input_file, output_file):
    # Chargement du fichier CSV
    try:
        df = pd.read_csv(input_file, encoding='utf-8')
    except FileNotFoundError:
        print(f"Le fichier {input_file} n'a pas été trouvé.")
        return
    except pd.errors.EmptyDataError:
        print("Le fichier est vide.")
        return

    # Appliquer le pré-nettoyage
    df_cleaned = pre_clean_csv(df)
    
    # Sauvegarder le fichier nettoyé
    df_cleaned.to_csv(output_file, index=False, encoding='utf-8')
    print(f"Le fichier nettoyé a été exporté avec succès : {output_file}")

# Exécution du nettoyage sur un fichier existant
input_csv = 'resultats_cve.csv'  # Remplacez par le chemin du fichier à nettoyer
output_csv = 'resultats_cve_nettoye.csv'  # Fichier de sortie nettoyé
clean_csv(input_csv, output_csv)
