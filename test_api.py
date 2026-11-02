#!/usr/bin/env python3
# =====================================================================
# Test et demonstration de l'API securisee - Partie 5.2
# ---------------------------------------------------------------------
# Prerequis :
#   1) Lancer l'API dans un AUTRE terminal :
#         python partie5_api/api_securisee.py
#   2) Installer la librairie requests (une seule fois) :
#         pip install requests
# Lancement :
#         python test_api.py
# Auteur : FENZI Melissa
# =====================================================================
import requests

BASE = "http://localhost:5001"


def section(titre):
    print("\n" + "=" * 64)
    print("  " + titre)
    print("=" * 64)


def verdict(obtenu, attendu):
    return "OK (attendu)" if obtenu == attendu else f"INATTENDU (attendu {attendu})"


def login(user, mdp):
    return requests.post(f"{BASE}/login", json={"username": user, "password": mdp})


# =====================================================================
section("1. AUTHENTIFICATION JWT + ACCES AUTORISE (role medecin)")
try:
    r = login("dr_martin", "medecin123")
except requests.exceptions.RequestException:
    print("L'API ne repond pas sur http://localhost:5001")
    print("Lance-la d'abord dans un autre terminal :")
    print("    python partie5_api/api_securisee.py")
    raise SystemExit(1)

if r.status_code == 429:
    print("Limite de debit encore active (test relance trop vite).")
    print("Redemarre l'API (Ctrl+C puis relance) ou attends 60 secondes, puis reessaie.")
    raise SystemExit(1)

print(f"POST /login (dr_martin)              -> {r.status_code}  {verdict(r.status_code, 200)}")
token = r.json().get("token")
print(f"Jeton JWT recu : {token[:40]}...")

entete = {"Authorization": f"Bearer {token}"}
r = requests.get(f"{BASE}/patients", headers=entete)
print(f"GET /patients (avec jeton valide)    -> {r.status_code}  {verdict(r.status_code, 200)}")
print(f"Reponse : {r.json()}")

# =====================================================================
section("2. CONTROLE D'ACCES RBAC : ROLE NON AUTORISE")
r2 = login("bob_compta", "compta123")
entete2 = {"Authorization": f"Bearer {r2.json().get('token')}"}
r = requests.get(f"{BASE}/dossiers", headers=entete2)
print(f"bob_compta (comptable) GET /dossiers -> {r.status_code}  {verdict(r.status_code, 403)}")
print(f"Reponse : {r.json()}")
print(">> Un comptable ne peut PAS lire les dossiers medicaux (moindre privilege).")

# =====================================================================
section("3. AUTHENTIFICATION MANQUANTE : SANS JETON")
r = requests.get(f"{BASE}/patients")
print(f"GET /patients (sans jeton)           -> {r.status_code}  {verdict(r.status_code, 401)}")
print(f"Reponse : {r.json()}")

# =====================================================================
section("4. LIMITATION DE DEBIT (anti force brute) : 5 requetes/min/IP")
print("Les 5 requetes autorisees cette minute sont deja consommees ;")
print("les requetes suivantes sont donc bloquees :")
for i in range(3):
    r = requests.get(f"{BASE}/patients", headers=entete)
    print(f"  Requete supplementaire {i + 1}         -> {r.status_code}  {verdict(r.status_code, 429)}")
print(">> Au-dela de 5 requetes/minute, l'API repond 429 (protection contre les abus).")

# =====================================================================
print("\n" + "=" * 64)
print("  BILAN  200 = autorise | 401 = non authentifie | 403 = interdit | 429 = trop de requetes")
print("=" * 64)
