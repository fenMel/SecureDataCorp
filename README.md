#  Projet SecureDataCorp — Sécurisation et restauration d'un SI

> Projet de rentrée **ESIS-1** — **FENZI Melissa**

Reconstruction et sécurisation complète du système d'information de **SecureDataCorp**,
une entreprise de données médicales victime d'une attaque par rançongiciel.
Le projet applique une logique de **défense en profondeur** à travers les 6 parties du cahier des charges.

---

##  Structure du dépôt

```
SecureDataCorp/
├── README.md
├── partie1_donnees/
│   ├── 01_creation_base.sql      # Création de la base + intégrité référentielle (1.1)
│   ├── 02_rbac.sql               # Rôles et droits d'accès - moindre privilège (1.2)
│   └── sauvegarde.sh             # Sauvegarde 3-2-1 chiffrée AES-256 (1.3)
├── partie2_detection/
│   ├── analyse_logs.py           # Détection d'anomalies : règles + IA (2.1)
│   └── reponse_auto.py           # Réponse automatisée aux incidents (2.2)
├── partie3_rgpd/
│   └── anonymisation.py          # Anonymisation à 3 niveaux + k-anonymat (3.2)
├── partie5_api/
│   ├── api_securisee.py          # API REST : JWT + RBAC + rate limiting (5.2)
│   └── openapi.yaml              # Documentation OpenAPI 3.0 / Swagger (5.3)
├── partie6_monitoring/
│   └── detection_ia_avancee.py   # 3 modèles d'IA : Isolation Forest, K-means, Random Forest (6.3)
└── docs/
    ├── Rapport_SecureDataCorp.docx
    └── Presentation_SecureDataCorp.pptx
```

---

##  Technologies utilisées

| Domaine | Outils |
|---|---|
| Base de données | MySQL 8.0 (Docker) |
| Virtualisation | Docker Desktop, VMware, Ubuntu Server 22.04 |
| Langages | SQL, Python 3, Bash |
| Sécurité / pentest | Nmap, Hydra, SQLMap, Suricata (IDS), ufw |
| Intelligence artificielle | Scikit-learn (Isolation Forest, K-means, Random Forest) |
| Monitoring | Metabase |
| API | Flask, PyJWT, OpenAPI 3.0 |

---

##  Prérequis et installation

```bash
# Bibliothèques Python nécessaires
pip install pandas scikit-learn faker flask pyjwt
```

---

##  Utilisation des scripts

### Partie 1 — Base de données
```bash
# Création de la base dans le conteneur MySQL
docker exec -i medicaldb mysql -uroot -p < partie1_donnees/01_creation_base.sql
docker exec -i medicaldb mysql -uroot -p < partie1_donnees/02_rbac.sql
```

### Partie 2 — Détection et réponse
```bash
python partie2_detection/analyse_logs.py      # analyse des logs (règles + IA)
python partie2_detection/reponse_auto.py       # réponse automatisée aux incidents
```

### Partie 3 — Anonymisation RGPD
```bash
python partie3_rgpd/anonymisation.py
```

### Partie 5 — API sécurisée
```bash
python partie5_api/api_securisee.py            # démarre l'API sur http://localhost:5001
```

### Partie 6 — IA avancée
```bash
python partie6_monitoring/detection_ia_avancee.py
```

---

##  Les 6 parties du projet

1. **Sécurisation des données** — base, chiffrement/RBAC, sauvegarde/DRP, pare-feu
2. **Détection des anomalies** — analyse de logs, réponse automatisée, IDS Suricata
3. **Conformité RGPD** — cartographie, anonymisation, plan de conformité
4. **Tests de pénétration** — pentest (Nmap, Hydra, SQLMap), plan de correctifs
5. **Création d'API** — comparatif no-code, sécurisation (JWT/RBAC), documentation
6. **Surveillance temps réel** — dashboards Metabase, automatisation, détection par IA

---

##  Avertissement

Les mots de passe présents dans les scripts sont des **exemples de démonstration**.
En production, ils seraient gérés via des variables d'environnement ou un coffre-fort de secrets.

---

*Projet réalisé dans le cadre de la formation ESIS — ESIC.*
