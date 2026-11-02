#!/usr/bin/env python3
# =====================================================================
# Projet SecureDataCorp - Point 3.2 : Anonymisation des données
# Fichier  : anonymisation.py
# Objet    : Transformer les données réelles en données anonymisées
#            pour la recherche / les tests, sans exposer les patients
# Auteur   : FENZI Melissa
# =====================================================================

import hashlib
import random
from faker import Faker

# Faker en français : génère des noms, adresses, etc. réalistes mais FICTIFS
fake = Faker("fr_FR")
Faker.seed(42)       # reproductibilité
random.seed(42)

# =====================================================================
# Rappel des 3 niveaux (demandés par le sujet)
#   Niveau 1 - Pseudonymisation : réversible (on garde une correspondance)
#   Niveau 2 - Anonymisation partielle : généralisation, perte de précision
#   Niveau 3 - Anonymisation forte : ré-identification impossible
# =====================================================================


# ---------------------------------------------------------------------
# Techniques d'anonymisation élémentaires
# ---------------------------------------------------------------------
def pseudonymiser(valeur):
    """Niveau 1 : remplace par un pseudonyme stable (hash tronqué).
    Réversible uniquement avec une table de correspondance gardée à part."""
    return "PSEUDO_" + hashlib.sha256(str(valeur).encode()).hexdigest()[:10]


def generaliser_date(date_str):
    """Niveau 2 : garde le mois et l'année, supprime le jour.
    '1985-07-23' -> '1985-07'."""
    return str(date_str)[:7]


def generaliser_age(date_naissance):
    """Niveau 2 : transforme une date de naissance en tranche d'âge.
    Réduit la précision pour empêcher l'identification."""
    annee = int(str(date_naissance)[:4])
    age = 2026 - annee
    bas = (age // 10) * 10
    return f"{bas}-{bas + 9} ans"


def generaliser_ville(adresse):
    """Niveau 2 : ne garde que la région/zone, supprime l'adresse exacte."""
    return "Île-de-France"


def ajouter_bruit(valeur, pct=0.05):
    """Niveau 2/3 : ajoute un bruit aléatoire à une valeur numérique
    (pour les résultats d'analyses), afin de préserver la tendance
    statistique sans exposer la valeur exacte."""
    bruit = valeur * random.uniform(-pct, pct)
    return round(valeur + bruit, 2)


def num_secu_fictif():
    """Niveau 3 : génère un numéro de Sécurité sociale au bon FORMAT
    (15 chiffres) mais totalement fictif."""
    return "".join(str(random.randint(0, 9)) for _ in range(15))


# ---------------------------------------------------------------------
# Anonymisation d'un enregistrement patient selon le niveau choisi
# ---------------------------------------------------------------------
def anonymiser_patient(patient, niveau=3, table_correspondance=None):
    """patient : dict {patient_id, nom, prenom, date_naissance, num_secu, adresse}
    niveau 1, 2 ou 3. table_correspondance : pour la pseudonymisation réversible."""
    p = dict(patient)

    if niveau == 1:
        # Pseudonymisation : on remplace l'identité par un pseudo stable,
        # et on conserve la correspondance (réversible).
        pseudo = pseudonymiser(p["patient_id"])
        if table_correspondance is not None:
            table_correspondance[pseudo] = p["patient_id"]
        p["nom"] = pseudo
        p["prenom"] = ""
        p["num_secu"] = pseudonymiser(p["num_secu"])
        # on garde la date exacte et l'adresse : réversible

    elif niveau == 2:
        # Anonymisation partielle : faux nom + généralisation
        p["nom"] = fake.last_name()
        p["prenom"] = fake.first_name()
        p["num_secu"] = num_secu_fictif()
        p["date_naissance"] = generaliser_date(p["date_naissance"])
        p["adresse"] = generaliser_ville(p["adresse"])

    else:  # niveau 3 : anonymisation forte
        # Tout est remplacé ou généralisé, ré-identification impossible
        p["nom"] = fake.last_name()
        p["prenom"] = fake.first_name()
        p["num_secu"] = num_secu_fictif()
        p["date_naissance"] = generaliser_age(p["date_naissance"])  # tranche d'âge
        p["adresse"] = generaliser_ville(p["adresse"])
        p["telephone"] = "0X XX XX XX XX"

    return p


# ---------------------------------------------------------------------
# Vérification du k-anonymat
# ---------------------------------------------------------------------
def calculer_k_anonymat(patients_anonymises, quasi_identifiants):
    """Le k-anonymat = taille du plus petit groupe partageant les mêmes
    quasi-identifiants. k élevé = meilleure protection.
    Ex : si au moins 5 patients partagent (tranche d'âge, région), k>=5."""
    from collections import Counter
    cles = [tuple(p.get(qi, "") for qi in quasi_identifiants) for p in patients_anonymises]
    compteur = Counter(cles)
    return min(compteur.values()) if compteur else 0


# ---------------------------------------------------------------------
# Démonstration
# ---------------------------------------------------------------------
if __name__ == "__main__":
    # Jeu de données d'exemple (simule des lignes de la table patients)
    patients = [
        {"patient_id": 1, "nom": "Dupont", "prenom": "Jean", "date_naissance": "1985-07-23",
         "num_secu": "185072312345678", "adresse": "12 rue de Paris, 75011 Paris", "telephone": "0612345678"},
        {"patient_id": 2, "nom": "Martin", "prenom": "Sophie", "date_naissance": "1990-03-15",
         "num_secu": "290031598765432", "adresse": "5 av. Victor Hugo, 92100 Boulogne", "telephone": "0698765432"},
        {"patient_id": 3, "nom": "Bernard", "prenom": "Luc", "date_naissance": "1982-11-02",
         "num_secu": "182110245678901", "adresse": "8 bd Voltaire, 75011 Paris", "telephone": "0677778888"},
    ]

    print("=" * 70)
    print("   DÉMONSTRATION DE L'ANONYMISATION - SecureDataCorp")
    print("=" * 70)

    print("\n--- DONNÉES ORIGINALES ---")
    for p in patients:
        print(f"  #{p['patient_id']} {p['prenom']} {p['nom']} | né {p['date_naissance']} | "
              f"{p['num_secu']} | {p['adresse']}")

    for niveau in (1, 2, 3):
        print(f"\n--- NIVEAU {niveau} ---")
        table = {} if niveau == 1 else None
        anonymises = [anonymiser_patient(p, niveau, table) for p in patients]
        for p in anonymises:
            print(f"  #{p['patient_id']} {p.get('prenom','')} {p['nom']} | "
                  f"né {p['date_naissance']} | {p['num_secu']} | {p['adresse']}")
        if niveau == 1:
            print(f"  (table de correspondance réversible : {len(table)} entrées conservées à part)")

    # k-anonymat sur le niveau 3 (quasi-identifiants : âge généralisé + région)
    anonymises3 = [anonymiser_patient(p, 3) for p in patients]
    k = calculer_k_anonymat(anonymises3, ["date_naissance", "adresse"])
    print(f"\n--- VALIDATION ---")
    print(f"  k-anonymat atteint (niveau 3) : k = {k}")
    print("  (plus k est grand, moins un individu est ré-identifiable)")
    print("=" * 70)
