# JATHNIEL-WEB-CRAWLER-PRO v5.0

Crawler web professionnel pour CTF / labo / pentests autorisés.

## Fonctionnalités
- Crawl multi-thread + extraction fichiers sensibles
- Forced Browsing (180+ chemins)
- Extraction & analyse DB (SQLite, dumps SQL, Redis…)
- Scan ports DB (MySQL, Postgres, Mongo, Redis, ES…)
- Subdomain enumeration
- Wayback Machine
- Interface Rich TUI
- Export JSON + HTML

## Installation
```bash
chmod +x install.sh && ./install.sh
source venv/bin/activate
python jathniel_crawler_pro.py