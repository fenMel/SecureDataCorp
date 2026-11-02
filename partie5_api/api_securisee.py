#!/usr/bin/env python3
# =====================================================================
# Projet SecureDataCorp - Point 5.2 : API sécurisée
# Fichier  : api_securisee.py
# Objet    : API REST exposant les données avec sécurité renforcée
# Sécurité : (1) authentification JWT  (2) RBAC par rôle  (3) rate limiting
# Auteur   : FENZI Melissa
# Lancement : python api_securisee.py   puis http://localhost:5001
# =====================================================================

from flask import Flask, request, jsonify
from functools import wraps
import jwt           # PyJWT : génération/vérification des jetons
import datetime
import hashlib
import time
import os            # pour lire les variables d'environnement

# Charge automatiquement le fichier .env s'il existe (pip install python-dotenv)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)

# Clé secrète pour signer les jetons JWT.
# Bonne pratique : lue depuis une variable d'environnement, jamais en clair.
# Définir JWT_SECRET_KEY dans un fichier .env ou dans l'environnement du système.
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-a-changer")

# ---------------------------------------------------------------------
# Base d'utilisateurs simulée (en réalité : table MySQL)
# Le mot de passe est stocké HACHÉ (SHA-256), jamais en clair.
# ---------------------------------------------------------------------
def hacher(mdp):
    return hashlib.sha256(mdp.encode()).hexdigest()

UTILISATEURS = {
    "dr_martin":    {"mdp": hacher("medecin123"),  "role": "medecin"},
    "bob_compta":   {"mdp": hacher("compta123"),   "role": "perso_admin"},
    "eva_analyste": {"mdp": hacher("analyste123"), "role": "analyste"},
    "alice_admin":  {"mdp": hacher("admin123"),    "role": "admin"},
}

# Matrice des droits : quel rôle peut accéder à quel endpoint
# (même logique de moindre privilège que le RBAC MySQL du point 1.2)
DROITS = {
    "medecin":     ["patients", "dossiers_medicaux", "analyses_labo"],
    "perso_admin": ["patients", "facturation"],
    "analyste":    ["patients", "dossiers_medicaux", "analyses_labo", "facturation"],
    "admin":       ["patients", "dossiers_medicaux", "analyses_labo", "facturation"],
}

# ---------------------------------------------------------------------
# Rate limiting simple : on compte les requêtes par IP
# ---------------------------------------------------------------------
REQUETES = {}             # { ip : [timestamps...] }
# Limite configurable via la variable d'environnement API_RATE_LIMIT
# (5 par défaut ; on peut la relever pour les tests complets par rôle).
LIMITE = int(os.getenv("API_RATE_LIMIT", "5"))   # requêtes max
FENETRE = 60              # par 60 secondes

def rate_limite(ip):
    maintenant = time.time()
    REQUETES.setdefault(ip, [])
    # On ne garde que les requêtes de la dernière minute
    REQUETES[ip] = [t for t in REQUETES[ip] if maintenant - t < FENETRE]
    if len(REQUETES[ip]) >= LIMITE:
        return False
    REQUETES[ip].append(maintenant)
    return True

# ---------------------------------------------------------------------
# Décorateur : exige un jeton JWT valide + vérifie le rôle
# ---------------------------------------------------------------------
def token_requis(table):
    def decorateur(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # 1. Rate limiting
            ip = request.remote_addr
            if not rate_limite(ip):
                return jsonify({"erreur": "Trop de requêtes, réessayez plus tard"}), 429

            # 2. Récupérer le jeton dans l'en-tête Authorization
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"erreur": "Jeton manquant"}), 401
            token = auth.split(" ")[1]

            # 3. Vérifier la signature et la validité du jeton
            try:
                donnees = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            except jwt.ExpiredSignatureError:
                return jsonify({"erreur": "Jeton expiré"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"erreur": "Jeton invalide"}), 401

            # 4. Vérifier le rôle (RBAC)
            role = donnees.get("role")
            if table not in DROITS.get(role, []):
                return jsonify({"erreur": f"Accès refusé : le rôle '{role}' "
                                f"n'a pas accès à '{table}'"}), 403

            return f(*args, **kwargs)
        return wrapper
    return decorateur

# ---------------------------------------------------------------------
# Endpoint de connexion : renvoie un jeton JWT si identifiants valides
# ---------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    # Rate limiting : indispensable sur le login pour bloquer la force brute
    ip = request.remote_addr
    if not rate_limite(ip):
        return jsonify({"erreur": "Trop de tentatives de connexion, "
                        "réessayez plus tard"}), 429

    data = request.get_json(force=True)
    user = data.get("username")
    mdp = data.get("password", "")

    compte = UTILISATEURS.get(user)
    if not compte or compte["mdp"] != hacher(mdp):
        return jsonify({"erreur": "Identifiants invalides"}), 401

    # Génération du jeton, valable 1 heure, contenant le rôle
    token = jwt.encode({
        "user": user,
        "role": compte["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({"token": token, "role": compte["role"]})

# ---------------------------------------------------------------------
# Endpoints protégés (un par table sensible)
# ---------------------------------------------------------------------
@app.route("/patients", methods=["GET"])
@token_requis("patients")
def get_patients():
    # En réalité : SELECT sur la base. Ici, données simulées.
    return jsonify({"table": "patients", "donnees": ["(données patients)"]})

@app.route("/dossiers", methods=["GET"])
@token_requis("dossiers_medicaux")
def get_dossiers():
    return jsonify({"table": "dossiers_medicaux", "donnees": ["(dossiers médicaux)"]})

@app.route("/facturation", methods=["GET"])
@token_requis("facturation")
def get_facturation():
    return jsonify({"table": "facturation", "donnees": ["(données facturation)"]})

# ---------------------------------------------------------------------
if __name__ == "__main__":
    print("API SecureDataCorp démarrée sur http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
