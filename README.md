# Projet SecureDataCorp — Sécurisation et restauration d'un SI

> Projet de rentrée **ESIS-1** — **FENZI Melissa**

Reconstruction et sécurisation complète du système d'information de **SecureDataCorp**,
une entreprise de données médicales victime d'une attaque par rançongiciel.
Le projet applique une logique de **défense en profondeur** à travers les 6 parties du cahier des charges.

---

## Structure du dépôt

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

## Technologies utilisées

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

## Installation & lancement (de A à Z)

> Le dépôt ne contient que le **code**. Pour le faire tourner, on reconstruit
> l'environnement autour des fichiers. La logique est une **chaîne** :
> **base de données → secrets → exécution**.
> La base MySQL est fournie par Docker (port 3307), les scripts SQL créent les
> tables et les droits, le fichier `.env` injecte les secrets, et les scripts
> Python se connectent à cette base.

### Prérequis
- **Docker** (pour la base MySQL)
- **Python 3** et **pip**
- **Git**

### Étape 1 — Récupérer le projet
```bash
git clone https://github.com/fenMel/SecureDataCorp.git
cd SecureDataCorp
```

### Étape 2 — Lancer la base de données MySQL (Docker)
```bash
docker run --name medicaldb \
  -e MYSQL_ROOT_PASSWORD=SecureData2026! \
  -p 3307:3306 -d mysql:8.0
```
`-p 3307:3306` expose le port interne 3306 du conteneur sur le port **3307** de
la machine : c'est par là que les scripts Python se connecteront
(`127.0.0.1:3307`).

### Étape 3 — Charger la structure de la base (scripts SQL)
```bash
docker exec -i medicaldb mysql -uroot -pSecureData2026! < partie1_donnees/01_creation_base.sql
docker exec -i medicaldb mysql -uroot -pSecureData2026! < partie1_donnees/02_rbac.sql
```
`docker exec -i ... < fichier.sql` injecte le contenu du script dans le MySQL du
conteneur : création des quatre tables, des contraintes d'intégrité et des rôles RBAC.

### Étape 4 — Installer les bibliothèques Python
```bash
pip install pandas scikit-learn faker flask pyjwt python-dotenv
```

### Étape 5 — Configurer les secrets (variables d'environnement)
```bash
cp .env.example .env     # puis éditer .env et renseigner ses valeurs
```
Les scripts lisent ces variables avec `os.getenv(...)` et ne contiennent donc
**aucun secret en clair**. Sans `.env`, les scripts tournent quand même (mode
simulation / clé par défaut).

### Étape 6 — Exécuter les scripts
```bash
python partie2_detection/analyse_logs.py       # analyse des logs (règles + IA)
python partie2_detection/reponse_auto.py        # réponse automatisée aux incidents
python partie3_rgpd/anonymisation.py            # anonymisation RGPD (3 niveaux)
python partie5_api/api_securisee.py             # démarre l'API sur http://localhost:5001
python partie6_monitoring/detection_ia_avancee.py   # détection IA (3 modèles)
```

---

## Les 6 parties du projet

1. **Sécurisation des données** — base, chiffrement/RBAC, sauvegarde/DRP, pare-feu
2. **Détection des anomalies** — analyse de logs, réponse automatisée, IDS Suricata
3. **Conformité RGPD** — cartographie, anonymisation, plan de conformité
4. **Tests de pénétration** — pentest (Nmap, Hydra, SQLMap), plan de correctifs
5. **Création d'API** — comparatif no-code, sécurisation (JWT/RBAC), documentation
6. **Surveillance temps réel** — dashboards Metabase, automatisation, détection par IA

---

## Avertissement

Les mots de passe présents dans les scripts sont des **exemples de démonstration**.
En production, ils seraient gérés via des variables d'environnement ou un coffre-fort de secrets.

---

*Projet réalisé dans le cadre de la formation ESIS — ESIC.*
