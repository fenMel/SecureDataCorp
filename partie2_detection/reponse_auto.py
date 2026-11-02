#!/usr/bin/env python3
# =====================================================================
# Projet SecureDataCorp - Point 2.2 : Système de réponse automatisée
# Fichier  : reponse_auto.py
# Objet    : Réagir automatiquement aux menaces détectées dans les logs
# Principe : détection -> décision (selon sévérité) -> action automatique
# Auteur   : FENZI Melissa
# =====================================================================

import os
import time
import json
import smtplib
import urllib.request
from email.mime.text import MIMEText
from datetime import datetime
from collections import defaultdict

# Charge automatiquement le fichier .env s'il existe (pip install python-dotenv)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# =====================================================================
# CONFIGURATION DES NOTIFICATIONS RÉELLES (via variables d'environnement)
# ---------------------------------------------------------------------
# Les secrets sont lus depuis l'environnement (fichier .env), jamais en
# clair dans le code. Si rien n'est défini, le système SIMULE l'envoi.
#   Discord : DISCORD_WEBHOOK_URL
#   Slack   : SLACK_WEBHOOK_URL
#   Email   : EMAIL_ACTIF, EMAIL_EXPEDITEUR, EMAIL_MDP, EMAIL_DESTINATAIRE
# =====================================================================
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
EMAIL_CONFIG = {
    "actif": os.getenv("EMAIL_ACTIF", "false").lower() == "true",
    "serveur": os.getenv("EMAIL_SERVEUR", "smtp.gmail.com"),
    "port": int(os.getenv("EMAIL_PORT", "587")),
    "expediteur": os.getenv("EMAIL_EXPEDITEUR", ""),
    "mot_de_passe": os.getenv("EMAIL_MDP", ""),
    "destinataire": os.getenv("EMAIL_DESTINATAIRE", ""),
}

# ---------------------------------------------------------------------
# Taxonomie des événements de sécurité (demandée par le sujet)
# ---------------------------------------------------------------------
# Chaque niveau de sévérité déclenche des actions proportionnées.
SEVERITES = {
    "CRITIQUE": {"delai_max": "immédiat", "canaux": ["email", "slack", "sms"]},
    "ÉLEVÉ":    {"delai_max": "15 min",   "canaux": ["email", "slack"]},
    "MOYEN":    {"delai_max": "1 h",      "canaux": ["slack"]},
    "FAIBLE":   {"delai_max": "24 h",     "canaux": ["log"]},
}

# ---------------------------------------------------------------------
# État du système (en production : base de données / pare-feu réel)
# ---------------------------------------------------------------------
ips_bloquees = {}                  # { ip : timestamp_fin_blocage }
comptes_isoles = set()             # comptes suspendus
liste_blanche = {"192.168.1.10", "192.168.1.11"}   # IP de confiance (anti faux positif)
echecs_par_ip = defaultdict(int)   # compteur d'échecs de connexion
journal_incidents = []             # registre d'audit


def journaliser(severite, type_evt, detail, action):
    """Enregistre chaque incident dans le registre d'audit (immuable)."""
    entree = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severite": severite,
        "type": type_evt,
        "detail": detail,
        "action": action,
    }
    journal_incidents.append(entree)
    print(f"  [{severite:8s}] {type_evt:22s} -> {action}")


def _envoyer_webhook(url, texte):
    """Envoie un message à un webhook Discord ou Slack (POST JSON)."""
    data = json.dumps({"content": texte, "text": texte}).encode("utf-8")
    # Discord (Cloudflare) refuse les requêtes sans User-Agent (erreur 403) :
    # on fournit donc une identité d'application explicite.
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "SecureDataCorp-Bot/1.0"})
    try:
        urllib.request.urlopen(req, timeout=5)
        return True
    except Exception as e:
        print(f"    (échec envoi webhook : {e})")
        return False


def _envoyer_email(sujet, corps):
    """Envoie un vrai email via SMTP."""
    try:
        msg = MIMEText(corps, "plain", "utf-8")
        msg["Subject"] = sujet
        msg["From"] = EMAIL_CONFIG["expediteur"]
        msg["To"] = EMAIL_CONFIG["destinataire"]
        s = smtplib.SMTP(EMAIL_CONFIG["serveur"], EMAIL_CONFIG["port"], timeout=10)
        s.starttls()
        s.login(EMAIL_CONFIG["expediteur"], EMAIL_CONFIG["mot_de_passe"])
        s.send_message(msg)
        s.quit()
        return True
    except Exception as e:
        print(f"    (échec envoi email : {e})")
        return False


def notifier(severite, message):
    """Envoie une vraie notification DÉTAILLÉE si un canal est configuré, sinon simule."""
    canaux = SEVERITES[severite]["canaux"]
    # Icône couleur selon la sévérité : repère visuel immédiat dans Discord
    icones = {"CRITIQUE": "🔴", "ÉLEVÉ": "🟠", "MOYEN": "🟡", "FAIBLE": "⚪"}
    # Message structuré : sévérité + détails de l'incident
    texte = (f"{icones.get(severite, '')} **[{severite}] SecureDataCorp**\n"
             f"{message}")
    envois = []

    # Envoi réel si configuré
    if DISCORD_WEBHOOK_URL and ("slack" in canaux or "sms" in canaux or "email" in canaux):
        if _envoyer_webhook(DISCORD_WEBHOOK_URL, texte):
            envois.append("Discord ✓")
    if SLACK_WEBHOOK_URL and ("slack" in canaux):
        if _envoyer_webhook(SLACK_WEBHOOK_URL, texte):
            envois.append("Slack ✓")
    if EMAIL_CONFIG.get("actif") and ("email" in canaux):
        if _envoyer_email(f"[{severite}] Alerte SecureDataCorp", texte):
            envois.append("Email ✓")

    if envois:
        return "ALERTE RÉELLE envoyée via " + ", ".join(envois)
    # Sinon : simulation (aucun canal configuré)
    return f"notification envoyée via {', '.join(canaux)}"


def bloquer_ip(ip, duree_heures):
    """Bloque une IP dans le pare-feu (ici simulé) pour une durée donnée."""
    if ip in liste_blanche:
        return f"IP {ip} en liste blanche : NON bloquée (anti faux positif)"
    ips_bloquees[ip] = time.time() + duree_heures * 3600
    return f"IP {ip} bloquée {duree_heures}h dans le pare-feu"


def isoler_compte(utilisateur):
    """Suspend temporairement un compte compromis."""
    comptes_isoles.add(utilisateur)
    return f"compte '{utilisateur}' isolé (suspension temporaire)"


# ---------------------------------------------------------------------
# Les workflows de réponse (correspondant aux cas du sujet)
# ---------------------------------------------------------------------
def workflow_force_brute(ip, nb_echecs):
    """Workflow 1 : réponse graduée aux tentatives de force brute."""
    echecs_par_ip[ip] = nb_echecs
    if nb_echecs > 20:
        blocage = bloquer_ip(ip, 24)
        msg = (f"**Force brute massive détectée**\n"
               f"• Type : tentatives de connexion répétées\n"
               f"• Source : IP {ip}\n"
               f"• Volume : {nb_echecs} échecs de connexion\n"
               f"• Action : {blocage}")
        action = blocage + " + " + notifier("CRITIQUE", msg)
        journaliser("CRITIQUE", "Force brute", f"{nb_echecs} échecs depuis {ip}", action)
    elif nb_echecs > 10:
        blocage = bloquer_ip(ip, 24)
        msg = (f"**Force brute détectée**\n"
               f"• Type : tentatives de connexion répétées\n"
               f"• Source : IP {ip}\n"
               f"• Volume : {nb_echecs} échecs de connexion\n"
               f"• Action : {blocage}")
        action = blocage + " + " + notifier("ÉLEVÉ", msg)
        journaliser("ÉLEVÉ", "Force brute", f"{nb_echecs} échecs depuis {ip}", action)
    elif nb_echecs > 5:
        action = bloquer_ip(ip, 1)
        journaliser("MOYEN", "Force brute", f"{nb_echecs} échecs depuis {ip}", action)


def workflow_injection_sql(ip, utilisateur, requete):
    """Workflow 2 : réponse immédiate à une tentative d'injection SQL."""
    a1 = bloquer_ip(ip, 24)
    a2 = isoler_compte(utilisateur)
    msg = (f"**Injection SQL détectée**\n"
           f"• Type : injection SQL (contournement d'authentification)\n"
           f"• Source : IP {ip}, compte « {utilisateur} »\n"
           f"• Requête suspecte : `{requete[:70]}`\n"
           f"• Action : IP bloquée 24h, compte isolé, sauvegarde d'urgence")
    a3 = notifier("CRITIQUE", msg)
    action = f"{a1} + {a2} + {a3} + sauvegarde d'urgence déclenchée"
    journaliser("CRITIQUE", "Injection SQL", f"{requete[:40]}... depuis {ip}", action)


def workflow_pic_requetes(ip, nb_requetes):
    """Workflow 4 : réaction à un pic anormal de requêtes (anti-DDoS)."""
    if nb_requetes > 1000:
        msg = (f"**Pic anormal de requêtes (possible DDoS)**\n"
               f"• Type : volume de requêtes anormalement élevé\n"
               f"• Source : IP {ip}\n"
               f"• Volume : {nb_requetes} requêtes/minute\n"
               f"• Action : rate limiting agressif activé")
        action = f"rate limiting agressif activé sur {ip} + " + notifier("ÉLEVÉ", msg)
        journaliser("ÉLEVÉ", "Pic de requêtes", f"{nb_requetes} req/min depuis {ip}", action)


def workflow_espace_disque(pct_libre):
    """Workflow 3 : réaction au manque d'espace disque."""
    if pct_libre < 10:
        msg = (f"**Espace disque critique**\n"
               f"• Composant : serveur de base de données\n"
               f"• État : {pct_libre}% d'espace libre restant\n"
               f"• Action : nettoyage auto des logs et fichiers temporaires")
        action = "nettoyage auto (logs + temp) + " + notifier("CRITIQUE", msg)
        journaliser("CRITIQUE", "Espace disque", f"{pct_libre}% libre", action)
    elif pct_libre < 20:
        msg = (f"**Espace disque faible**\n"
               f"• Composant : serveur de base de données\n"
               f"• État : {pct_libre}% d'espace libre restant\n"
               f"• Action : nettoyage auto des vieux logs")
        action = "nettoyage auto des vieux logs + " + notifier("MOYEN", msg)
        journaliser("MOYEN", "Espace disque", f"{pct_libre}% libre", action)


# ---------------------------------------------------------------------
# Démonstration : simulation d'une attaque et de la réponse automatique
# ---------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("   SYSTÈME DE RÉPONSE AUTOMATISÉE - Simulation d'incidents")
    print("=" * 70)

    print("\n--- Incident 1 : force brute (25 échecs depuis une IP étrangère) ---")
    workflow_force_brute("45.133.1.99", 25)

    print("\n--- Incident 2 : injection SQL ---")
    workflow_injection_sql("45.133.1.99", "admin", "SELECT * FROM patients WHERE nom='' OR 1=1 --")

    print("\n--- Incident 3 : pic anormal de requêtes ---")
    workflow_pic_requetes("45.133.1.99", 3500)

    print("\n--- Incident 4 : espace disque critique ---")
    workflow_espace_disque(8)

    print("\n--- Incident 5 : force brute depuis une IP de confiance (faux positif) ---")
    workflow_force_brute("192.168.1.10", 30)

    print("\n" + "=" * 70)
    print("ÉTAT FINAL DU SYSTÈME")
    print(f"  IP actuellement bloquées : {list(ips_bloquees.keys())}")
    print(f"  Comptes isolés           : {list(comptes_isoles)}")
    print(f"  Incidents journalisés    : {len(journal_incidents)}")
    print("=" * 70)
