#!/bin/bash
# =====================================================================
# Projet SecureDataCorp - Point 1.3 : Sauvegarde automatisée
# Fichier  : sauvegarde.sh
# Objet    : Sauvegarde chiffrée de la base, stratégie 3-2-1
# Auteur   : FENZI Melissa
# Usage    : ./sauvegarde.sh   (à planifier via cron)
# =====================================================================

# --- Configuration ---------------------------------------------------
DB_NAME="SecureDataCorp"
DB_USER="root"
DB_PASS="********"                         # en prod : variable d'environnement
CONTENEUR="medicaldb"                      # conteneur Docker MySQL
DATE=$(date +%Y%m%d_%H%M%S)
DOSSIER_LOCAL="/backups/local"             # support 1 : disque local
DOSSIER_NAS="/backups/nas"                 # support 2 : NAS
DOSSIER_EXTERNE="/backups/externe"         # support 3 : hors site (3-2-1)
RETENTION_JOURS=30

# --- Création des dossiers -------------------------------------------
mkdir -p "$DOSSIER_LOCAL" "$DOSSIER_NAS" "$DOSSIER_EXTERNE"

FICHIER="sauvegarde_${DB_NAME}_${DATE}.sql"

echo "=== Sauvegarde $DB_NAME - $DATE ==="

# --- 1. Export de la base (mysqldump) --------------------------------
# --single-transaction : cohérence sans verrouiller la base
docker exec "$CONTENEUR" mysqldump -u"$DB_USER" -p"$DB_PASS" \
    --single-transaction --routines --triggers \
    "$DB_NAME" > "$DOSSIER_LOCAL/$FICHIER"
echo "[1/4] Export SQL réalisé : $FICHIER"

# --- 2. Chiffrement de la sauvegarde (GPG / AES-256) -----------------
# La sauvegarde chiffrée ne peut être lue sans la clé : protège même
# si un attaquant accède au fichier (leçon de l'attaque initiale).
gpg --batch --yes --passphrase "CLE_SECRETE" \
    --symmetric --cipher-algo AES256 \
    "$DOSSIER_LOCAL/$FICHIER"
rm -f "$DOSSIER_LOCAL/$FICHIER"            # on ne garde que la version chiffrée
FICHIER_CHIFFRE="$FICHIER.gpg"
echo "[2/4] Sauvegarde chiffrée (AES-256) : $FICHIER_CHIFFRE"

# --- 3. Application de la stratégie 3-2-1 ----------------------------
# 3 copies, 2 supports différents, 1 copie hors site
cp "$DOSSIER_LOCAL/$FICHIER_CHIFFRE" "$DOSSIER_NAS/"
cp "$DOSSIER_LOCAL/$FICHIER_CHIFFRE" "$DOSSIER_EXTERNE/"
echo "[3/4] Copies 3-2-1 : local + NAS + hors site"

# --- 4. Purge des sauvegardes de plus de 30 jours --------------------
find "$DOSSIER_LOCAL" "$DOSSIER_NAS" "$DOSSIER_EXTERNE" \
    -name "*.gpg" -type f -mtime +$RETENTION_JOURS -delete
echo "[4/4] Purge des sauvegardes > $RETENTION_JOURS jours"

echo "=== Sauvegarde terminée avec succès ==="

# ---------------------------------------------------------------------
# Planification (cron) :
#   # sauvegarde incrémentale quotidienne à 2h du matin
#   0 2 * * *   /chemin/sauvegarde.sh
#   # sauvegarde complète hebdomadaire le dimanche
#   0 3 * * 0   /chemin/sauvegarde.sh
#
# Restauration :
#   gpg --decrypt sauvegarde_xxx.sql.gpg > restore.sql
#   docker exec -i medicaldb mysql -uroot -p < restore.sql
# ---------------------------------------------------------------------
