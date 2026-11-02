#!/usr/bin/env python3
# =====================================================================
# Projet SecureDataCorp - Point 6.3 : Détection comportementale par IA
# Fichier  : detection_ia_avancee.py
# Objet    : Aller au-delà des règles avec plusieurs modèles de ML
# Modèles  : Isolation Forest (non supervisé) + K-means (clustering)
#            + Random Forest (supervisé)
# Auteur   : FENZI Melissa
# =====================================================================

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score

np.random.seed(42)

# ---------------------------------------------------------------------
# 1. Génération d'un jeu de données de comportements utilisateurs
# ---------------------------------------------------------------------
def generer_donnees():
    """Simule le comportement de différents profils d'utilisateurs,
    plus quelques comptes compromis (anomalies)."""
    lignes = []

    # Profil 1 : médecins consultants réguliers (journée, volume modéré)
    for _ in range(40):
        lignes.append({
            "heure": np.random.randint(8, 19),
            "nb_requetes": np.random.randint(20, 80),
            "nb_tables": np.random.randint(2, 4),
            "volume_extrait": np.random.randint(10, 100),
            "ip_externe": 0,
            "label": 0,   # normal
        })

    # Profil 2 : personnel administratif (facturation)
    for _ in range(30):
        lignes.append({
            "heure": np.random.randint(9, 18),
            "nb_requetes": np.random.randint(10, 50),
            "nb_tables": np.random.randint(1, 2),
            "volume_extrait": np.random.randint(5, 50),
            "ip_externe": 0,
            "label": 0,
        })

    # Profil 3 : analystes (gros volumes mais en journée, interne)
    for _ in range(20):
        lignes.append({
            "heure": np.random.randint(9, 18),
            "nb_requetes": np.random.randint(80, 150),
            "nb_tables": np.random.randint(3, 5),
            "volume_extrait": np.random.randint(100, 400),
            "ip_externe": 0,
            "label": 0,
        })

    # Comptes compromis (anomalies) : nuit, IP externe, extraction massive
    for _ in range(10):
        lignes.append({
            "heure": np.random.randint(0, 5),
            "nb_requetes": np.random.randint(200, 500),
            "nb_tables": np.random.randint(4, 5),
            "volume_extrait": np.random.randint(5000, 50000),
            "ip_externe": 1,
            "label": 1,   # anomalie
        })

    return pd.DataFrame(lignes).sample(frac=1, random_state=42).reset_index(drop=True)


# ---------------------------------------------------------------------
# 2. Modèle 1 : Isolation Forest (non supervisé)
# ---------------------------------------------------------------------
def modele_isolation_forest(X):
    modele = IsolationForest(contamination=0.1, random_state=42)
    pred = modele.fit_predict(X)              # -1 = anomalie, 1 = normal
    return (pred == -1).astype(int)           # 1 = anomalie détectée


# ---------------------------------------------------------------------
# 3. Modèle 2 : K-means (regroupement en profils de comportement)
# ---------------------------------------------------------------------
def modele_kmeans(X, n_clusters=4):
    """Regroupe les utilisateurs par profils similaires. Le cluster le plus
    petit et le plus éloigné correspond souvent aux comportements anormaux."""
    km = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    clusters = km.fit_predict(X)
    # On repère le plus petit cluster (comportements rares = suspects)
    tailles = pd.Series(clusters).value_counts()
    cluster_suspect = tailles.idxmin()
    return clusters, cluster_suspect, tailles


# ---------------------------------------------------------------------
# 4. Modèle 3 : Random Forest (supervisé, avec labels)
# ---------------------------------------------------------------------
def modele_random_forest(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y)
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    return {
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
        "f1": f1_score(y_test, y_pred, zero_division=0),
        "importances": dict(zip(X.columns, rf.feature_importances_.round(3))),
    }


# ---------------------------------------------------------------------
# Démonstration
# ---------------------------------------------------------------------
if __name__ == "__main__":
    df = generer_donnees()
    features = ["heure", "nb_requetes", "nb_tables", "volume_extrait", "ip_externe"]
    X = df[features]
    y = df["label"]

    # Normalisation (important pour K-means)
    X_norm = pd.DataFrame(StandardScaler().fit_transform(X), columns=features)

    print("=" * 70)
    print("   DÉTECTION COMPORTEMENTALE AVANCÉE PAR IA - SecureDataCorp")
    print("=" * 70)
    print(f"\nJeu de données : {len(df)} comportements ({y.sum()} anomalies réelles)")

    # --- Modèle 1 : Isolation Forest ---
    pred_if = modele_isolation_forest(X_norm)
    detectes_if = pred_if.sum()
    vrais_if = ((pred_if == 1) & (y == 1)).sum()
    print(f"\n[Modèle 1 - Isolation Forest, non supervisé]")
    print(f"  Anomalies signalées : {detectes_if} | dont vraies : {vrais_if}/{y.sum()}")

    # --- Modèle 2 : K-means ---
    clusters, suspect, tailles = modele_kmeans(X_norm)
    print(f"\n[Modèle 2 - K-means, clustering]")
    print(f"  Profils identifiés (tailles des clusters) : {dict(tailles)}")
    print(f"  Cluster le plus rare (suspect) : cluster {suspect} ({tailles[suspect]} membres)")
    anomalies_dans_suspect = y[clusters == suspect].sum()
    print(f"  Anomalies réelles dans ce cluster : {anomalies_dans_suspect}/{tailles[suspect]}")

    # --- Modèle 3 : Random Forest ---
    res = modele_random_forest(X, y)
    print(f"\n[Modèle 3 - Random Forest, supervisé]")
    print(f"  Précision : {res['precision']:.2f} | Recall : {res['recall']:.2f} | F1 : {res['f1']:.2f}")
    print(f"  Importance des caractéristiques : {res['importances']}")

    print("\n" + "=" * 70)
    print("CONCLUSION : les 3 modèles sont complémentaires.")
    print(" - Isolation Forest : détecte sans exemples d'attaques")
    print(" - K-means : regroupe les profils et isole les comportements rares")
    print(" - Random Forest : très précis quand on dispose de données labellisées")
    print("=" * 70)
