#!/usr/bin/env python3
# =====================================================================
# Projet SecureDataCorp - Point 2.1 : Analyse automatisée des logs
# Fichier  : analyse_logs.py
# Objet    : Détecter les activités suspectes dans les logs de la base
# Méthodes : (1) règles de détection  (2) IA - Isolation Forest
# Auteur   : FENZI Melissa
# =====================================================================

import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest

# ---------------------------------------------------------------------
# 1. Chargement des logs
# ---------------------------------------------------------------------
# Deux sources possibles :
#   - option A : lire directement la table mysql.general_log (via mysql-connector)
#   - option B : lire un fichier CSV exporté (plus simple, pas de dépendance)
# Ici on utilise un jeu de données de démonstration contenant des
# activités NORMALES et des activités ANORMALES (simulées), afin de
# montrer que la détection fonctionne.

def charger_donnees_demo():
    """Génère un jeu de logs de démonstration (normal + anormal)."""
    donnees = []

    # --- Activité normale : connexions aux heures de bureau ---
    for i in range(80):
        donnees.append({
            "timestamp": f"2026-10-25 {9 + i % 8:02d}:{i % 60:02d}:00",
            "utilisateur": np.random.choice(["dr_martin", "bob_compta", "eva_analyste"]),
            "ip": np.random.choice(["192.168.1.10", "192.168.1.11", "192.168.1.12"]),
            "type_commande": "Query",
            "requete": np.random.choice([
                "SELECT * FROM patients WHERE patient_id = 42",
                "SELECT diagnostic FROM dossiers_medicaux WHERE patient_id = 7",
                "UPDATE facturation SET montant = 150 WHERE facture_id = 3",
            ]),
            "succes": 1,
        })

    # --- Anomalie 1 : force brute (beaucoup d'échecs depuis une IP ---
    for i in range(25):
        donnees.append({
            "timestamp": f"2026-10-25 03:{i % 60:02d}:00",   # 3h du matin
            "utilisateur": "admin",
            "ip": "45.133.1.99",                              # IP étrangère
            "type_commande": "Connect",
            "requete": "",
            "succes": 0,                                      # échec
        })

    # --- Anomalie 2 : tentative d'injection SQL ---
    for i in range(5):
        donnees.append({
            "timestamp": f"2026-10-25 03:{30 + i:02d}:00",
            "utilisateur": "admin",
            "ip": "45.133.1.99",
            "type_commande": "Query",
            "requete": "SELECT * FROM patients WHERE nom = '' OR 1=1 --",
            "succes": 1,
        })

    # --- Anomalie 3 : extraction massive de données ---
    for i in range(3):
        donnees.append({
            "timestamp": f"2026-10-25 04:{i:02d}:00",
            "utilisateur": "admin",
            "ip": "45.133.1.99",
            "type_commande": "Query",
            "requete": "SELECT * FROM patients LIMIT 100000",
            "succes": 1,
        })

    return pd.DataFrame(donnees)


# ---------------------------------------------------------------------
# 2. Détection par règles (patterns connus)
# ---------------------------------------------------------------------
def detecter_par_regles(df):
    """Applique des règles de sécurité et retourne les alertes."""
    alertes = []

    # Règle 1 : force brute = > 5 échecs de connexion depuis une même IP
    echecs = df[(df["type_commande"] == "Connect") & (df["succes"] == 0)]
    for ip, nb in echecs.groupby("ip").size().items():
        if nb > 5:
            alertes.append({
                "severite": "ÉLEVÉ",
                "type": "Force brute",
                "detail": f"{nb} échecs de connexion depuis l'IP {ip}",
            })

    # Règle 2 : injection SQL = motifs suspects dans les requêtes
    motifs_injection = ["OR 1=1", "--", "UNION SELECT", "; DROP", "' OR '"]
    for _, ligne in df.iterrows():
        requete = str(ligne["requete"]).upper()
        for motif in motifs_injection:
            if motif.upper() in requete:
                alertes.append({
                    "severite": "CRITIQUE",
                    "type": "Injection SQL",
                    "detail": f"Motif '{motif}' détecté depuis {ligne['ip']} ({ligne['utilisateur']})",
                })
                break

    # Règle 3 : extraction massive = LIMIT élevé
    for _, ligne in df.iterrows():
        requete = str(ligne["requete"]).upper()
        if "LIMIT" in requete:
            try:
                limite = int(requete.split("LIMIT")[1].strip().split()[0])
                if limite > 1000:
                    alertes.append({
                        "severite": "CRITIQUE",
                        "type": "Exfiltration",
                        "detail": f"Extraction de {limite} lignes depuis {ligne['ip']}",
                    })
            except (ValueError, IndexError):
                pass

    # Règle 4 : activité nocturne (entre 2h et 5h du matin)
    df["heure"] = pd.to_datetime(df["timestamp"]).dt.hour
    nocturne = df[(df["heure"] >= 2) & (df["heure"] <= 5)]
    if len(nocturne) > 10:
        alertes.append({
            "severite": "MOYEN",
            "type": "Activité nocturne",
            "detail": f"{len(nocturne)} actions entre 2h et 5h du matin",
        })

    return alertes


# ---------------------------------------------------------------------
# 3. Détection par IA (Isolation Forest, non supervisée)
# ---------------------------------------------------------------------
def detecter_par_ia(df):
    """Utilise Isolation Forest pour repérer les lignes atypiques."""
    # On transforme les données en caractéristiques numériques (features)
    df = df.copy()
    df["heure"] = pd.to_datetime(df["timestamp"]).dt.hour
    df["longueur_requete"] = df["requete"].astype(str).str.len()
    df["est_echec"] = (df["succes"] == 0).astype(int)
    # Encodage simple de l'IP (étrangère = 1, interne = 0)
    df["ip_externe"] = (~df["ip"].astype(str).str.startswith("192.168")).astype(int)

    features = df[["heure", "longueur_requete", "est_echec", "ip_externe"]]

    # contamination = proportion d'anomalies attendue (~15 %)
    modele = IsolationForest(contamination=0.15, random_state=42, n_estimators=100)
    df["anomalie"] = modele.fit_predict(features)   # -1 = anomalie, 1 = normal

    anomalies = df[df["anomalie"] == -1]
    return anomalies


# ---------------------------------------------------------------------
# 4. Génération du rapport
# ---------------------------------------------------------------------
def generer_rapport(df, alertes, anomalies_ia):
    print("=" * 60)
    print("   RAPPORT D'ANALYSE DE SÉCURITÉ - SecureDataCorp")
    print("   Généré le", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 60)
    print(f"\nTotal d'événements analysés : {len(df)}")

    print(f"\n--- ALERTES PAR RÈGLES ({len(alertes)}) ---")
    if alertes:
        for a in alertes:
            print(f"  [{a['severite']:8s}] {a['type']:16s} : {a['detail']}")
    else:
        print("  Aucune alerte.")

    print(f"\n--- ANOMALIES DÉTECTÉES PAR IA ({len(anomalies_ia)}) ---")
    if len(anomalies_ia) > 0:
        apercu = anomalies_ia[["timestamp", "utilisateur", "ip", "requete"]].head(10)
        for _, l in apercu.iterrows():
            req = (l["requete"][:40] + "...") if len(str(l["requete"])) > 40 else l["requete"]
            print(f"  {l['timestamp']} | {l['utilisateur']:12s} | {l['ip']:15s} | {req}")
    else:
        print("  Aucune anomalie.")

    print("\n" + "=" * 60)


# ---------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------
if __name__ == "__main__":
    df = charger_donnees_demo()
    alertes = detecter_par_regles(df)
    anomalies_ia = detecter_par_ia(df)
    generer_rapport(df, alertes, anomalies_ia)
