-- =====================================================================
-- Projet SecureDataCorp - Point 1.2 : Contrôle d'accès RBAC
-- Fichier  : 02_rbac.sql
-- Objet    : Rôles MySQL, privilèges différenciés, utilisateurs
-- Principe : moindre privilège (chaque rôle a le minimum nécessaire)
-- =====================================================================

USE SecureDataCorp;

-- ---------------------------------------------------------------------
-- 1. Création des rôles
-- ---------------------------------------------------------------------
-- Un rôle est un "conteneur de privilèges". On l'attribue ensuite
-- à un ou plusieurs utilisateurs. MySQL 8.0 gère ça nativement.
CREATE ROLE IF NOT EXISTS 'role_admin';
CREATE ROLE IF NOT EXISTS 'role_medecin';
CREATE ROLE IF NOT EXISTS 'role_perso_admin';
CREATE ROLE IF NOT EXISTS 'role_analyste';
CREATE ROLE IF NOT EXISTS 'role_app_api';

-- ---------------------------------------------------------------------
-- 2. Attribution des privilèges à chaque rôle
-- ---------------------------------------------------------------------

-- Administrateur : tous les droits sur toute la base
GRANT ALL PRIVILEGES ON SecureDataCorp.* TO 'role_admin';

-- Médecin : lecture seule sur patients,
--           lecture/écriture sur dossiers_medicaux et analyses_labo,
--           aucun accès à facturation.
GRANT SELECT ON SecureDataCorp.patients           TO 'role_medecin';
GRANT SELECT, INSERT, UPDATE, DELETE
      ON SecureDataCorp.dossiers_medicaux          TO 'role_medecin';
GRANT SELECT, INSERT, UPDATE, DELETE
      ON SecureDataCorp.analyses_labo              TO 'role_medecin';

-- Personnel administratif : lecture seule sur patients,
--                           lecture/écriture sur facturation.
GRANT SELECT ON SecureDataCorp.patients            TO 'role_perso_admin';
GRANT SELECT, INSERT, UPDATE, DELETE
      ON SecureDataCorp.facturation                TO 'role_perso_admin';

-- Analyste : lecture seule sur toutes les tables (données à pseudonymiser).
GRANT SELECT ON SecureDataCorp.patients            TO 'role_analyste';
GRANT SELECT ON SecureDataCorp.dossiers_medicaux   TO 'role_analyste';
GRANT SELECT ON SecureDataCorp.analyses_labo       TO 'role_analyste';
GRANT SELECT ON SecureDataCorp.facturation         TO 'role_analyste';

-- Application API : accès restreint au strict nécessaire (lecture).
GRANT SELECT ON SecureDataCorp.patients            TO 'role_app_api';
GRANT SELECT ON SecureDataCorp.dossiers_medicaux   TO 'role_app_api';
GRANT SELECT ON SecureDataCorp.analyses_labo       TO 'role_app_api';

-- ---------------------------------------------------------------------
-- 3. Création des utilisateurs et attribution des rôles
-- ---------------------------------------------------------------------
-- Note : les mots de passe ci-dessous sont des exemples de démonstration.
-- En production, ils seraient générés aléatoirement et gérés via un
-- coffre-fort de secrets (voir volet "gestion des clés" du 1.2).

CREATE USER IF NOT EXISTS 'alice_admin'@'%'   IDENTIFIED BY 'ChangeMe_Admin!2026';
CREATE USER IF NOT EXISTS 'dr_martin'@'%'     IDENTIFIED BY 'ChangeMe_Medecin!2026';
CREATE USER IF NOT EXISTS 'bob_compta'@'%'    IDENTIFIED BY 'ChangeMe_Compta!2026';
CREATE USER IF NOT EXISTS 'eva_analyste'@'%'  IDENTIFIED BY 'ChangeMe_Analyste!2026';
CREATE USER IF NOT EXISTS 'svc_api'@'%'       IDENTIFIED BY 'ChangeMe_Api!2026';

-- Attribution des rôles aux utilisateurs
GRANT 'role_admin'       TO 'alice_admin'@'%';
GRANT 'role_medecin'     TO 'dr_martin'@'%';
GRANT 'role_perso_admin' TO 'bob_compta'@'%';
GRANT 'role_analyste'    TO 'eva_analyste'@'%';
GRANT 'role_app_api'     TO 'svc_api'@'%';

-- IMPORTANT : un rôle attribué n'est pas actif tant qu'il n'est pas
-- "activé" par défaut à la connexion. On force l'activation automatique.
SET DEFAULT ROLE ALL TO
    'alice_admin'@'%',
    'dr_martin'@'%',
    'bob_compta'@'%',
    'eva_analyste'@'%',
    'svc_api'@'%';

-- Appliquer immédiatement les changements de privilèges
FLUSH PRIVILEGES;

-- ---------------------------------------------------------------------
-- 4. Vérifications (pour tes captures d'écran)
-- ---------------------------------------------------------------------
-- Liste des rôles et utilisateurs créés
SELECT User, Host FROM mysql.user
WHERE User IN ('role_admin','role_medecin','role_perso_admin','role_analyste','role_app_api',
               'alice_admin','dr_martin','bob_compta','eva_analyste','svc_api')
ORDER BY User;

-- Privilèges accordés au rôle médecin (preuve du moindre privilège)
SHOW GRANTS FOR 'role_medecin';

-- Privilèges effectifs de l'utilisateur médecin (via son rôle)
SHOW GRANTS FOR 'dr_martin'@'%' USING 'role_medecin';
