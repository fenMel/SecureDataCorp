#!/usr/bin/env python3
# =====================================================================
# Test RBAC par role - Partie 5.2 (matrice des acces)
# ---------------------------------------------------------------------
# Ce test complet envoie beaucoup de requetes : lance l'API avec une
# limite de debit elevee (sinon la limite de 5/min bloque le test).
#
#   Windows (cmd)        : set API_RATE_LIMIT=1000 && python partie5_api\api_securisee.py
#   Windows (PowerShell) : $env:API_RATE_LIMIT=1000 ; python partie5_api\api_securisee.py
#
# Puis, dans un autre terminal :  python test_roles.py
# Auteur : FENZI Melissa
# =====================================================================
import requests

BASE = "http://localhost:5001"

# Les 4 comptes de test (identifiant, mot de passe, metier)
COMPTES = [
    ("dr_martin",    "medecin123",  "Medecin"),
    ("bob_compta",   "compta123",   "Comptable"),
    ("eva_analyste", "analyste123", "Analyste"),
    ("alice_admin",  "admin123",    "Admin"),
]

# Les 3 tables exposees par l'API
ENDPOINTS = ["/patients", "/dossiers", "/facturation"]


def login(user, mdp):
    return requests.post(f"{BASE}/login", json={"username": user, "password": mdp})


print("=" * 74)
print("  MATRICE DES ACCES PAR ROLE (RBAC) - API SecureDataCorp")
print("=" * 74)
print(f"{'Utilisateur':<14}{'Role':<12}{'/patients':<16}{'/dossiers':<16}{'/facturation':<16}")
print("-" * 74)

for user, mdp, role in COMPTES:
    try:
        r = login(user, mdp)
    except requests.exceptions.RequestException:
        print("L'API ne repond pas sur http://localhost:5001")
        print("Lance-la d'abord (voir l'en-tete de ce fichier).")
        raise SystemExit(1)

    if r.status_code == 429:
        print("\nLimite de debit atteinte : relance l'API avec API_RATE_LIMIT=1000")
        print("(voir l'en-tete de ce fichier).")
        raise SystemExit(1)

    entete = {"Authorization": f"Bearer {r.json().get('token')}"}
    resultats = []
    for route in ENDPOINTS:
        rr = requests.get(f"{BASE}{route}", headers=entete)
        if rr.status_code == 200:
            resultats.append("OK (200)")
        elif rr.status_code == 403:
            resultats.append("REFUSE (403)")
        else:
            resultats.append(f"? ({rr.status_code})")
    print(f"{user:<14}{role:<12}{resultats[0]:<16}{resultats[1]:<16}{resultats[2]:<16}")

print("-" * 74)
print("  OK (200) = autorise par le role    |    REFUSE (403) = interdit par le RBAC")
print("=" * 74)
