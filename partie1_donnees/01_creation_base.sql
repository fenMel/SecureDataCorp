-- =====================================================================
-- Projet SecureDataCorp - Point 1.1 : Remise en place de la base
-- Fichier  : 01_creation_base.sql
-- Objet    : Recréation de la base MedicalDB et des 4 tables principales
-- SGBD     : MySQL 8.0 sur Ubuntu Server 22.04
-- Auteur   : FENZI Melissa
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Création de la base de données
-- ---------------------------------------------------------------------
-- utf8mb4 = jeu de caractères complet (accents, caractères spéciaux).
-- Indispensable pour des noms/adresses français sans corruption.
CREATE DATABASE IF NOT EXISTS SecureDataCorp
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE SecureDataCorp;

-- ---------------------------------------------------------------------
-- 2. Table patients
-- ---------------------------------------------------------------------
-- Table "parente" : elle doit être créée EN PREMIER car les trois
-- autres tables la référencent via une clé étrangère (patient_id).
CREATE TABLE patients (
    patient_id      INT AUTO_INCREMENT PRIMARY KEY,     -- clé primaire auto-incrémentée
    nom             VARCHAR(50)  NOT NULL,              -- obligatoire
    prenom          VARCHAR(50)  NOT NULL,              -- obligatoire
    date_naissance  DATE         NOT NULL,              -- obligatoire
    num_secu        VARCHAR(15)  NOT NULL UNIQUE,       -- n° sécu : unique + obligatoire
    adresse         VARCHAR(100),                       -- facultatif
    telephone       VARCHAR(20)                         -- facultatif
) ENGINE=InnoDB;
-- ENGINE=InnoDB : obligatoire pour que les clés étrangères soient
-- réellement appliquées (MyISAM les ignore silencieusement).

-- ---------------------------------------------------------------------
-- 3. Table dossiers_medicaux
-- ---------------------------------------------------------------------
CREATE TABLE dossiers_medicaux (
    dossier_id        INT AUTO_INCREMENT PRIMARY KEY,
    patient_id        INT          NOT NULL,            -- clé étrangère obligatoire
    date_consultation DATE         NOT NULL,
    diagnostic        TEXT         NOT NULL,
    prescription      TEXT,
    -- Contrainte d'intégrité référentielle :
    -- un dossier ne peut exister que pour un patient existant.
    CONSTRAINT fk_dossier_patient
        FOREIGN KEY (patient_id) REFERENCES patients(patient_id)
        ON DELETE CASCADE      -- si un patient est supprimé, ses dossiers le sont aussi
        ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 4. Table analyses_labo
-- ---------------------------------------------------------------------
CREATE TABLE analyses_labo (
    analyse_id    INT AUTO_INCREMENT PRIMARY KEY,
    patient_id    INT          NOT NULL,
    date_analyse  DATE         NOT NULL,
    type_analyse  VARCHAR(50)  NOT NULL,
    resultats     TEXT,
    CONSTRAINT fk_analyse_patient
        FOREIGN KEY (patient_id) REFERENCES patients(patient_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 5. Table facturation
-- ---------------------------------------------------------------------
CREATE TABLE facturation (
    facture_id     INT AUTO_INCREMENT PRIMARY KEY,
    patient_id     INT            NOT NULL,
    date_facture   DATE           NOT NULL,
    montant        DECIMAL(10,2)  NOT NULL,             -- 10 chiffres dont 2 décimales
    mode_paiement  VARCHAR(20),
    ref_assurance  VARCHAR(30),
    CONSTRAINT fk_facture_patient
        FOREIGN KEY (patient_id) REFERENCES patients(patient_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 6. Vérifications (à exécuter pour tes captures d'écran)
-- ---------------------------------------------------------------------
SHOW TABLES;                        -- liste les 4 tables créées
DESCRIBE patients;                  -- structure de la table patients
DESCRIBE dossiers_medicaux;         -- structure + voir la clé étrangère

-- Preuve que les clés étrangères sont bien en place :
SELECT
    TABLE_NAME,
    COLUMN_NAME,
    CONSTRAINT_NAME,
    REFERENCED_TABLE_NAME,
    REFERENCED_COLUMN_NAME
FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
WHERE TABLE_SCHEMA = 'SecureDataCorp'
  AND REFERENCED_TABLE_NAME IS NOT NULL;
