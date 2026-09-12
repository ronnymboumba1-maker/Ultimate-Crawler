# 🕷️ JATHNIEL-WEB-CRAWLER-PRO v5.0

> Crawler web professionnel avec détection et extraction de bases de données exposées,
> chasse aux flags/credentials, et analyse automatique.

![Version](https://img.shields.io/badge/version-5.0-red)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-Educational-green)
![Status](https://img.shields.io/badge/status-stable-brightgreen)

---

## ⚠️ AVERTISSEMENT LÉGAL

**Ce programme est destiné UNIQUEMENT à :**

- 🎓 L'apprentissage en cybersécurité
- 🏴 Les CTF (Capture The Flag)
- 🧪 Les laboratoires personnels (DVWA, WebGoat, Juice Shop)
- 🔐 Les tests d'intrusion **autorisés par écrit**

**Il est STRICTEMENT INTERDIT d'utiliser cet outil sur :**
- Un site que vous ne possédez pas
- Un système sans autorisation écrite préalable
- Toute infrastructure tierce

**L'auteur décline toute responsabilité** en cas d'usage illégal.
Utilisez toujours dans un cadre légal et éthique.

---

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Architecture](#-architecture)
- [Configuration](#-configuration)
- [Exemples](#-exemples)
- [Sortie / Résultats](#-sortie--résultats)
- [FAQ](#-faq)
- [Changelog](#-changelog)
- [Licence](#-licence)

---

## ✨ Fonctionnalités

### 🕷️ Crawling
- Crawl multi-threadé avec vraie parallélisation (queue thread-safe)
- Gestion de la profondeur, des limites de pages et des assets
- Respect de `robots.txt` (optionnel)
- Suivi des redirections configurable
- Support SSL désactivable (labos avec certificats auto-signés)

### 🗄️ Détection & Extraction de bases de données
- **Magic bytes** : identification même si l'extension est trompeuse (`admin.bin` → SQLite)
- Support **SQLite**, **MySQL dump**, **PostgreSQL dump**, **Redis RDB**, **MongoDB BSON**
- **Décompression automatique** : gzip, bz2, xz
- **Extraction des archives ZIP** contenant des DB
- **Support SQLite WAL / SHM** (données récentes non committées)
- Analyse : tables, colonnes, lignes, échantillons
- Protection **Zip Slip** et **Zip Bomb**

### 🎯 Forced Browsing
- Wordlist intégrée de 100+ chemins sensibles
- Détection des **faux positifs** (404 custom renvoyant 200)
- Backups datés, `.env`, `wp-config.php`, `docker-compose.yml`, etc.

### 🚨 Sécurité avancée
- Détection et **dump automatique** des `.git/` exposés
- Extraction de **credentials** (passwords, API keys, connection strings)
- **Chasse aux flags** : `flag{...}`, `HTB{...}`, `CTF{...}`, patterns génériques
- **Grep local** post-crawl sur tout le dump

### 📊 Reporting
- Export **JSON** (structuré, scriptable)
- Export **HTML** (rapport visuel avec CSS)
- Export **CSV** (analyse Excel)
- Logs fichier + console (`crawler.log`)

### 🖥️ Interface
- Menu interactif coloré
- **Mode CLI** scriptable (parfait pour CI/CTF automatisé)
- Option **changer de cible** en cours d'exécution
- Statistiques temps réel

---

## 🔧 Installation

### Prérequis
- **Python 3.8+**
- **pip**
- Système : Linux, macOS, WSL (Windows natif non testé)

### Étapes

```bash
# 1. Cloner / télécharger
git clone <repo> jathniel-crawler
cd jathniel-crawler

# 2. Environnement virtuel
python3 -m venv venv
source venv/bin/activate           # Linux/macOS
# venv\Scripts\activate            # Windows

# 3. Dépendances Python
pip install -r requirements.txt

# 4. (Optionnel) Outils système pour fonctionnalités avancées
sudo apt install sqlite3 seclists  # Debian/Ubuntu/Kali
pip install git-dumper             # Dump .git/ exposés
```

### Vérification

```bash
python3 crawler.py --help
```

---

## 🚀 Utilisation

### Mode interactif (menu)

```bash
python3 crawler.py
```

Menu principal :

```
┌──────────────────────────────────────────────────────────┐
│  MENU PRINCIPAL - WEB CRAWLER PRO v5.0                   │
├──────────────────────────────────────────────────────────┤
│  1.  Lancer un crawl complet                             │
│  2.  Crawl + extraction de bases de donnees              │
│  3.  Changer la cible actuelle                           │
│  4.  Telecharger un fichier specifique                   │
│  5.  Voir les resultats du crawl                         │
│  6.  Voir les fichiers sensibles trouves                 │
│  7.  Voir les bases de donnees extraites                 │
│  8.  Voir les flags / credentials trouves                │
│  9.  Forced browsing sur la cible actuelle               │
│  10. Grep local (chercher dans tout le dump)             │
│  11. Exporter les resultats (JSON/HTML/CSV)              │
│  12. Configuration                                       │
│  13. Statistiques du crawl                               │
│  14. Aide / Documentation                                │
│  0.  Quitter                                             │
└──────────────────────────────────────────────────────────┘
```

### Mode CLI (rapide / scriptable)

```bash
# Crawl complet d'une cible
python3 crawler.py https://target.lab --quick

# Avec options
python3 crawler.py https://target.lab --quick \
    --depth 3 \
    --threads 20 \
    --no-git \
    --no-grep
```

**Options CLI :**

| Option | Description | Défaut |
|---|---|---|
| `url` | URL cible (positionnel) | requis en CLI |
| `--quick` | Mode sans menu | `False` |
| `--depth N` | Profondeur max de crawl | `3` |
| `--threads N` | Nombre de threads | `10` |
| `--no-forced-browse` | Désactive le forced browsing | `False` |
| `--no-git` | Désactive la détection `.git/` | `False` |
| `--no-flag-hunt` | Désactive la chasse aux flags | `False` |
| `--no-grep` | Désactive le grep local | `False` |

---

## 🏗️ Architecture

```
JATHNIELCrawlerPro
│
├── Crawling
│   ├── crawl_complete()      # Orchestrateur principal
│   ├── crawl_page()          # Crawl d'une page
│   ├── extract_links()       # Extraction des liens
│   └── extract_assets()      # Extraction des assets
│
├── Détection
│   ├── search_sensitive_in_page()   # Cherche du sensible dans le HTML
│   ├── download_sensitive_file()    # Télécharge + classifie
│   ├── identify_file_type()         # Magic bytes
│   └── forced_browse()              # Wordlist
│
├── Analyse DB
│   ├── analyze_database()           # Router
│   ├── analyze_sqlite()             # SQLite + WAL/SHM
│   ├── analyze_sql_dump()           # MySQL/PostgreSQL
│   ├── analyze_compressed_db()      # gzip/bz2/xz
│   ├── analyze_zip_archive()        # Zip + Zip Slip
│   ├── analyze_redis_dump()         # Redis RDB
│   ├── analyze_bson()               # MongoDB
│   └── analyze_generic_db()         # Fallback
│
├── Sécurité
│   ├── check_git_exposed()          # Détection .git/
│   ├── grep_credentials()           # Credentials dans dump
│   ├── hunt_flags_in_text()         # Flags dans HTML/texte
│   ├── hunt_flags_in_db()           # Flags dans DB
│   └── local_grep()                 # Grep récursif post-crawl
│
├── Reporting
│   ├── export_html_report()
│   ├── export_csv_report()
│   └── export_results()             # JSON
│
└── UI
    ├── run()                        # Menu interactif
    ├── show_*()                     # Affichages
    └── cli_mode()                   # Mode scriptable
```

---

## ⚙️ Configuration

Toute la config est dans `self.config` (dict Python) :

```python
{
    'max_depth': 3,               # Profondeur de crawl
    'max_pages': 500,             # Pages max
    'threads': 10,                # Threads parallèles
    'timeout': 30,                # Timeout HTTP (s)
    'delay': 0.5,                 # Délai entre requêtes (s)
    'output_dir': './crawled_sites',
    'download_sensitive': True,   # Télécharger les sensibles
    'download_assets': True,      # Télécharger les assets
    'verify_ssl': False,          # Vérification SSL
    'analyze_db': True,           # Analyse auto des DB
    'auto_extract_zip': True,     # Extraction auto des ZIP
    'forced_browse': True,        # Forced browsing
    'check_git': True,            # Détection .git/
    'hunt_flags': True,           # Chasse aux flags
    'local_grep': True,           # Grep local final
}
```

Modifiable via le menu **12. Configuration** ou en éditant `self.config` dans le code.

---

## 💡 Exemples

### Exemple 1 : Reconnaissance complète sur un labo

```bash
python3 crawler.py http://dvwa.local --quick --depth 3 --threads 15
```

Résultat :
```
📄 Pages: 87
📁 Fichiers sensibles: 12
🗄️ Bases de donnees: 2
🚩 Flags: 3
💎 Credentials: 5
```

### Exemple 2 : CTF éclair

```bash
python3 crawler.py http://target.ctf --quick --threads 20
```

### Exemple 3 : Menu interactif avec changement de cible

```bash
python3 crawler.py
# → Choisir 3 pour changer de cible
# → Choisir 1 pour crawl
# → Choisir 7 pour voir les DB
# → Choisir 11 pour exporter
```

### Exemple 4 : Analyser une DB trouvée manuellement

```bash
sqlite3 crawled_sites/example.com/databases/database.sqlite
sqlite> .tables
sqlite> .dump
```

---

## 📂 Sortie / Résultats

Pour une cible `https://example.com`, structure :

```
crawled_sites/
└── example.com/
    ├── pages/                  # Pages HTML crawlees
    ├── assets/                 # CSS, JS, images
    ├── sensitive/              # Fichiers sensibles (.env, configs)
    ├── databases/              # Bases de donnees + .headers
    ├── git_dump/               # Dump .git/ si exposé
    ├── extracted_xxx/          # Fichiers extraits des ZIP
    ├── logs/
    │   └── crawler.log         # Log complet de la session
    └── reports/
        ├── crawl_report_YYYYMMDD_HHMMSS.json
        ├── crawl_report_YYYYMMDD_HHMMSS.html
        ├── crawl_report_YYYYMMDD_HHMMSS.csv
        └── final_report.json   # En mode CLI
```

### Formats d'export

| Format | Usage | Contenu |
|---|---|---|
| **JSON** | Scriptable, parsing auto | Toutes les données structurées |
| **HTML** | Rapport visuel, présentation | Stats, DB, flags, credentials |
| **CSV** | Excel, analyse | Tableaux plats |

---

## ❓ FAQ

### Le crawler est lent, comment accélérer ?

```bash
python3 crawler.py <url> --quick --threads 30 --depth 2
```

Et dans la config, diminue `delay` à `0.1`.

### J'obtiens des erreurs SSL sur un labo

C'est normal si le labo a un certificat auto-signé. `verify_ssl: False` est déjà le défaut.

### Le forced browsing renvoie plein de faux positifs

Le `_is_real_file()` filtre les 404 custom qui renvoient 200. Si ton labo a un vrai 404 custom qui ressemble à une page normale, ajoute des motifs dans la fonction.

### Comment ajouter mes propres chemins à la wordlist ?

Édite la constante `COMMON_DB_PATHS` en haut du fichier :

```python
COMMON_DB_PATHS = [
    # ... existant ...
    "mon_backup_custom.sql",
    "admin_secret/",
]
```

Ou utilise SecLists :

```python
# Charger dynamiquement
with open('/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt') as f:
    COMMON_DB_PATHS.extend(line.strip() for line in f)
```

### Comment analyser une DB sans refaire le crawl ?

Utilise l'option **4. Télécharger un fichier specifique** dans le menu, ou :

```python
from crawler import JATHNIELCrawlerPro
c = JATHNIELCrawlerPro()
c.analyze_database('/path/to/db.sqlite', 'sqlite', 'db.sqlite')
```

### Le programme crash sur une grosse DB

Augmente la limite dans `download_sensitive_file` :

```python
max_size = 200 * 1024 * 1024  # 200 Mo au lieu de 50
```

### Comment désactiver complètement le forced browsing ?

En CLI : `--no-forced-browse`
En menu : Configuration (option 12).

---

## 📝 Changelog

### v5.0 — Édition Pentest/CTF complète (actuelle)

**Ajouts :**
- 🎯 Forced browsing avec wordlist intégrée
- 🚨 Détection et dump des `.git/` exposés
- 💎 Extraction de credentials (passwords, API keys, connection strings)
- 🚩 Chasse aux flags (`flag{...}`, `HTB{...}`, `CTF{...}`)
- 📎 Support SQLite WAL / SHM
- 🔍 Grep local post-crawl
- 🖥️ Mode CLI scriptable (`--quick`)
- 🔄 Option "changer de cible"
- 📊 Heuristique anti-404 custom
- 📝 Logging fichier + console
- 💾 Sauvegarde des headers HTTP

**Correctifs :**
- ✅ Race conditions (queue thread-safe)
- ✅ Vrai parallélisme avec workers natifs
- ✅ Re-fetch évité (lecture locale des fichiers)
- ✅ Injection SQL (validation table + quoting)
- ✅ Zip Slip + Zip Bomb
- ✅ Fuite de fichiers temporaires
- ✅ `sqlite3` lock (copie tempfile)

### v4.0

- Détection de bases de données exposées
- Identification par magic bytes
- Ouverture automatique des SQLite + dump des tables
- Parsing des dumps SQL
- Rapport structuré

### v3.0 et antérieur

- Crawler de base
- Détection de fichiers sensibles
- Export JSON

---

## 🤝 Contribution

Les issues et PR sont bienvenues **pour un usage éducatif/légal uniquement**.

Avant de contribuer :
- ✅ Code testé sur DVWA/WebGoat
- ✅ Respect PEP8 (autant que possible)
- ✅ Pas de fonctionnalité offensive gratuite
- ✅ Documentation à jour

---

## 📄 Licence

**Usage éducatif uniquement.** Aucune garantie.

Ce projet est fourni tel quel pour apprendre la cybersécurité,
en CTF, et dans des laboratoires personnels.
Toute utilisation sur des systèmes tiers sans autorisation
est illégale et strictement interdite.

---

## 👤 Auteur

**JATHNIEL** — Projet éducatif de cybersécurité

> *"Apprends en construisant, comprends en cassant, respecte les règles."*

---

## 🔗 Ressources utiles

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [DVWA](https://github.com/digininja/DVWA) — Damn Vulnerable Web App
- [WebGoat](https://github.com/WebGoat/WebGoat)
- [Juice Shop](https://github.com/juice-shop/juice-shop)
- [HackTricks](https://book.hacktricks.xyz/) — Techniques de pentest
- [SecLists](https://github.com/danielmiessler/SecLists) — Wordlists
- [PortSwigger Academy](https://portswigger.net/web-security) — Labs gratuits
- [TryHackMe](https://tryhackme.com) / [HackTheBox](https://hackthebox.com) — CTF et labs

---

**⭐ Si ce projet t'a aidé dans ton apprentissage, garde-le dans un cadre légal !**
