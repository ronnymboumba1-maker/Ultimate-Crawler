#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JATHNIEL-WEB-CRAWLER-PRO v5.0
Crawler web pro + Forced Browsing + Extraction DB + Port Scan
+ Subdomain Enum + Wayback + Rich TUI

Usage éducatif / CTF / labo / pentests autorisés uniquement.
"""

import os
import sys
import time
import json
import re
import hashlib
import threading
import socket
import urllib3
import shutil
import sqlite3
import gzip
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque, defaultdict
from typing import Dict, List, Optional, Any

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich import box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# ==================== FORCED BROWSING WORDLIST (180+) ====================

FORCED_PATHS = [
    # Config / env
    "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.old",
    "/config.php", "/configuration.php", "/config.inc.php", "/settings.php",
    "/wp-config.php", "/wp-config.php.bak", "/config.yml", "/config.yaml",
    "/application.yml", "/application.properties", "/web.config", "/app.config",
    "/database.yml", "/db.php", "/db.ini", "/php.ini", "/.htaccess", "/.htpasswd",
    # Git / VCS
    "/.git/HEAD", "/.git/config", "/.git/index", "/.gitignore", "/.svn/entries",
    "/.hg/hgrc", "/.DS_Store", "/Thumbs.db",
    # Backups
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql", "/dump.sql",
    "/database.sql", "/backup/", "/backups/", "/old/", "/temp/", "/tmp/",
    "/www.zip", "/site.zip", "/html.zip", "/public.zip", "/src.zip",
    # Databases
    "/database.db", "/data.db", "/app.db", "/users.db", "/test.db",
    "/database.sqlite", "/data.sqlite", "/app.sqlite", "/database.sqlite3",
    "/dump.rdb", "/redis.rdb", "/mongodb.archive", "/pg_dump.sql",
    # Admin
    "/admin/", "/administrator/", "/admin.php", "/login.php", "/signin.php",
    "/panel/", "/dashboard/", "/cpanel/", "/webmail/", "/phpmyadmin/",
    "/adminer.php", "/adminer/", "/manager/", "/console/", "/backend/",
    # API
    "/api/", "/api/v1/", "/api/v2/", "/graphql", "/swagger/", "/swagger-ui/",
    "/api-docs/", "/openapi.json", "/swagger.json", "/v1/", "/v2/",
    # Logs / debug
    "/logs/", "/log/", "/debug/", "/error.log", "/access.log", "/app.log",
    "/laravel.log", "/storage/logs/", "/var/log/",
    # Docker / CI
    "/Dockerfile", "/docker-compose.yml", "/.dockerenv", "/Makefile",
    "/.travis.yml", "/.gitlab-ci.yml", "/Jenkinsfile", "/Vagrantfile",
    # Dependencies
    "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
    "/yarn.lock", "/requirements.txt", "/Pipfile", "/Gemfile", "/pom.xml",
    # Discovery
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/security.txt",
    "/humans.txt", "/.well-known/security.txt", "/clientaccesspolicy.xml",
    # Common sensitive
    "/server-status", "/server-info", "/phpinfo.php", "/info.php", "/test.php",
    "/shell.php", "/cmd.php", "/eval.php", "/upload.php", "/filemanager/",
    "/elfinder/", "/ckeditor/", "/tinymce/",
    # More backups / old
    "/index.php.bak", "/index.html.bak", "/config.bak", "/.bak", "/.old",
    "/.save", "/.swp", "/~", "/archive/", "/archives/", "/export/",
    "/data/", "/db/", "/sql/", "/dumps/", "/mysql/", "/sqlite/",
    # Auth keys
    "/id_rsa", "/id_rsa.pub", "/id_dsa", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/authorized_keys", "/known_hosts",
    # CMS specific
    "/wp-admin/", "/wp-login.php", "/wp-content/debug.log", "/xmlrpc.php",
    "/user/login", "/user/register", "/admin/login", "/administrator/index.php",
]

DB_PORTS = {
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    9300: "Elasticsearch (transport)",
    11211: "Memcached",
    1433: "MSSQL",
    1521: "Oracle",
}

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
    "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
    "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar",
    "wiki", "web", "media", "email", "images", "img", "www1", "intranet",
    "portal", "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4",
    "www3", "dns", "search", "staging", "server", "mx1", "chat", "wap", "my",
    "svn", "mail1", "sites", "proxy", "ads", "online", "remote", "mx2", "ftp2",
    "api2", "git", "gitlab", "jenkins", "ci", "monitor", "status", "db", "db1",
]


class CrawlerPro:
    def __init__(self):
        self.config = {
            "max_depth": 3,
            "max_pages": 400,
            "threads": 12,
            "timeout": 12,
            "delay": 0.3,
            "user_agent": "JATHNIEL-Crawler-Pro/5.0 (CTF/Lab)",
            "output_dir": "./crawled_sites",
            "verify_ssl": False,
            "forced_browsing": True,
            "port_scan": True,
            "subdomain_enum": True,
            "wayback": True,
            "analyze_db": True,
        }
        self.target_url = ""
        self.target_domain = ""
        self.base_scheme = "https"
        self.visited = set()
        self.queue = deque()
        self.lock = threading.Lock()
        self.results = {
            "pages": [],
            "sensitive": [],
            "databases": [],
            "db_contents": {},
            "admin": [],
            "emails": set(),
            "forms": [],
            "techs": set(),
            "subdomains": [],
            "open_ports": [],
            "wayback_urls": [],
            "forced_hits": [],
            "stats": {
                "pages": 0, "sensitive": 0, "databases": 0,
                "start": None, "end": None, "duration": 0,
            },
        }
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.config["user_agent"]})
        self.session.verify = self.config["verify_ssl"]

    # ---------- UI ----------
    def banner(self):
        console.print(Panel.fit(
            "[bold red]🕷️  JATHNIEL-WEB-CRAWLER-PRO v5.0[/]\n"
            "[cyan]Crawl · Forced Browsing · DB · Ports · Subdomains · Wayback[/]\n"
            "[dim]CTF / Lab / Authorized only[/]",
            border_style="cyan",
        ))

    def menu(self):
        table = Table(show_header=False, box=box.ROUNDED, border_style="cyan")
        table.add_column("N", style="yellow", width=4)
        table.add_column("Action", style="white")
        rows = [
            ("1", "Crawl complet (pages + assets + sensibles)"),
            ("2", "Crawl + Forced Browsing + DB + Ports"),
            ("3", "Forced Browsing seul"),
            ("4", "Scan ports DB"),
            ("5", "Subdomain enumeration"),
            ("6", "Wayback Machine"),
            ("7", "Voir résultats"),
            ("8", "Voir bases de données"),
            ("9", "Exporter (JSON / HTML)"),
            ("10", "Configuration"),
            ("0", "Quitter"),
        ]
        for n, a in rows:
            table.add_row(n, a)
        console.print(table)
        if self.target_url:
            console.print(f"[dim]Cible : {self.target_url} | Pages : {self.results['stats']['pages']} | "
                          f"Sensibles : {self.results['stats']['sensitive']} | DB : {self.results['stats']['databases']}[/]")

    # ---------- Helpers ----------
    def _get(self, url: str, timeout: Optional[int] = None) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=timeout or self.config["timeout"], allow_redirects=True)
        except Exception:
            return None

    def identify_type(self, content: bytes) -> str:
        sigs = {
            b"SQLite format 3\x00": "sqlite",
            b"PK\x03\x04": "zip",
            b"\x1f\x8b": "gzip",
            b"-- MySQL dump": "mysql_dump",
            b"-- PostgreSQL database dump": "postgres_dump",
            b"REDIS": "redis_dump",
        }
        for magic, name in sigs.items():
            if content.startswith(magic):
                return name
        preview = content[:4000]
        if b"CREATE TABLE" in preview or b"INSERT INTO" in preview:
            return "sql_dump"
        return "unknown"

    def is_interesting(self, content: bytes) -> bool:
        low = content[:8000].lower()
        keys = [b"password", b"api_key", b"secret", b"token", b"begin rsa",
                b"begin private", b"create table", b"sqlite format"]
        return any(k in low for k in keys)

    # ---------- Crawl ----------
    def crawl(self, url: str, full: bool = True):
        self.target_url = url.rstrip("/")
        parsed = urlparse(self.target_url)
        self.target_domain = parsed.netloc
        self.base_scheme = parsed.scheme or "https"

        out = Path(self.config["output_dir"]) / self.target_domain
        for d in ["pages", "sensitive", "databases", "reports"]:
            (out / d).mkdir(parents=True, exist_ok=True)

        self.results["stats"]["start"] = datetime.now()
        self.visited.clear()
        self.queue.clear()
        self.queue.append((self.target_url, 0))

        console.print(f"\n[cyan]🕷️  Crawl de[/] {self.target_url}")
        console.print(f"[dim]Dossier : {out}[/]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("Crawl...", total=self.config["max_pages"])

            with ThreadPoolExecutor(max_workers=self.config["threads"]) as pool:
                futures = {}
                while (self.queue or futures) and len(self.visited) < self.config["max_pages"]:
                    while self.queue and len(futures) < self.config["threads"] * 2:
                        u, depth = self.queue.popleft()
                        if u in self.visited:
                            continue
                        self.visited.add(u)
                        futures[pool.submit(self._crawl_page, u, depth, out)] = u

                    if not futures:
                        break

                    done, _ = as_completed(futures), None
                    for fut in list(futures.keys()):
                        if fut.done():
                            futures.pop(fut, None)
                            progress.update(task, completed=len(self.visited))
                            try:
                                fut.result()
                            except Exception:
                                pass
                    time.sleep(self.config["delay"])

        if full and self.config["forced_browsing"]:
            self.forced_browsing(out)
        if full and self.config["port_scan"]:
            self.scan_ports()
        if full and self.config["subdomain_enum"]:
            self.enum_subdomains()
        if full and self.config["wayback"]:
            self.wayback()

        self._post_analysis()
        self.results["stats"]["end"] = datetime.now()
        self.results["stats"]["duration"] = (
            self.results["stats"]["end"] - self.results["stats"]["start"]
        ).total_seconds()

        console.print(f"\n[green]✅ Crawl terminé[/] — "
                      f"Pages: {self.results['stats']['pages']} | "
                      f"Sensibles: {self.results['stats']['sensitive']} | "
                      f"DB: {self.results['stats']['databases']} | "
                      f"{self.results['stats']['duration']:.1f}s")

    def _crawl_page(self, url: str, depth: int, out: Path):
        resp = self._get(url)
        if not resp or resp.status_code != 200:
            return

        content = resp.content
        text = resp.text

        # Sauvegarde page
        name = urlparse(url).path.replace("/", "_") or "index"
        name = re.sub(r"[^\w\-.]", "_", name)[:80]
        if not name.endswith(".html"):
            name += ".html"
        (out / "pages" / name).write_text(text, encoding="utf-8", errors="ignore")

        with self.lock:
            self.results["pages"].append({"url": url, "status": resp.status_code, "size": len(content)})
            self.results["stats"]["pages"] += 1

        # Liens
        if depth < self.config["max_depth"]:
            soup = BeautifulSoup(text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("#") or href.startswith("javascript:"):
                    continue
                abs_url = urljoin(url, href)
                if self.target_domain in urlparse(abs_url).netloc and abs_url not in self.visited:
                    with self.lock:
                        self.queue.append((abs_url, depth + 1))

        # Fichiers sensibles dans la page
        self._find_sensitive_in_html(text, url, out)

        # Emails / forms / tech
        for m in re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text):
            with self.lock:
                self.results["emails"].add(m)

        for form in BeautifulSoup(text, "html.parser").find_all("form"):
            with self.lock:
                self.results["forms"].append({
                    "url": url,
                    "action": urljoin(url, form.get("action", "")),
                    "method": form.get("method", "GET").upper(),
                })

        for tech, patterns in {
            "WordPress": ["wp-content", "wp-includes"],
            "Laravel": ["csrf-token", "laravel"],
            "Django": ["csrfmiddlewaretoken"],
            "React": ["react", "react-dom"],
            "Vue": ["vue.js", "vue.min"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
        }.items():
            if any(p in text.lower() for p in patterns):
                with self.lock:
                    self.results["techs"].add(tech)

    def _find_sensitive_in_html(self, html: str, base: str, out: Path):
        candidates = set()
        for m in re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', html, re.I):
            candidates.add(urljoin(base, m))
        for m in re.findall(r'(/[a-zA-Z0-9_\-./]+\.(?:env|sql|db|sqlite|sqlite3|bak|old|zip|tar\.gz|log|yml|yaml|json|pem|key))', html, re.I):
            candidates.add(urljoin(base, m))

        for u in candidates:
            if any(u.lower().endswith(ext) for ext in [
                ".env", ".sql", ".db", ".sqlite", ".sqlite3", ".bak", ".old",
                ".zip", ".log", ".yml", ".yaml", ".pem", ".key", ".dump", ".rdb"
            ]) or any(x in u.lower() for x in ["wp-config", "config.php", ".git", "backup"]):
                self._download_sensitive(u, out)

    def _download_sensitive(self, url: str, out: Path) -> bool:
        if url in self.visited:
            return False
        with self.lock:
            self.visited.add(url)

        resp = self._get(url)
        if not resp or resp.status_code != 200:
            return False
        content = resp.content
        if len(content) > 40 * 1024 * 1024:
            return False

        real = self.identify_type(content)
        is_db = real in ("sqlite", "mysql_dump", "postgres_dump", "sql_dump", "redis_dump", "gzip") or \
                any(url.lower().endswith(e) for e in [".sql", ".db", ".sqlite", ".sqlite3", ".dump", ".rdb"])

        fname = urlparse(url).path.split("/")[-1] or hashlib.md5(url.encode()).hexdigest()[:10]
        fname = re.sub(r"[^\w\-.]", "_", fname)[:90]
        dest_dir = out / ("databases" if is_db else "sensitive")
        path = dest_dir / fname
        if path.exists():
            path = dest_dir / f"{path.stem}_{hashlib.md5(url.encode()).hexdigest()[:6]}{path.suffix}"
        path.write_bytes(content)

        info = {
            "url": url, "filename": path.name, "size": len(content),
            "path": str(path), "real_type": real,
        }
        with self.lock:
            if is_db:
                self.results["databases"].append(info)
                self.results["stats"]["databases"] += 1
                console.print(f"  [magenta]🗄️  DB[/] {path.name} ({len(content)} o) ← {url}")
                if self.config["analyze_db"]:
                    self._analyze_db(str(path), real, path.name)
            else:
                self.results["sensitive"].append(info)
                self.results["stats"]["sensitive"] += 1
                console.print(f"  [red]🔴 Sensible[/] {path.name} ← {url}")
        return True

    # ---------- Forced Browsing ----------
    def forced_browsing(self, out: Optional[Path] = None):
        if not self.target_url:
            console.print("[red]Aucune cible[/]")
            return
        if out is None:
            out = Path(self.config["output_dir"]) / self.target_domain
            out.mkdir(parents=True, exist_ok=True)
            (out / "sensitive").mkdir(exist_ok=True)
            (out / "databases").mkdir(exist_ok=True)

        console.print(f"\n[yellow]🔫 Forced Browsing[/] ({len(FORCED_PATHS)} chemins)...")
        base = f"{self.base_scheme}://{self.target_domain}"

        hits = []
        with ThreadPoolExecutor(max_workers=15) as pool:
            futs = {pool.submit(self._probe, base + p): p for p in FORCED_PATHS}
            for fut in as_completed(futs):
                path = futs[fut]
                try:
                    ok, url, size = fut.result()
                    if ok:
                        hits.append(url)
                        console.print(f"  [green]✓[/] {url} ({size} o)")
                        self._download_sensitive(url, out)
                except Exception:
                    pass

        self.results["forced_hits"] = hits
        console.print(f"[green]→ {len(hits)} hits[/]")

    def _probe(self, url: str):
        resp = self._get(url, timeout=8)
        if resp and resp.status_code == 200 and len(resp.content) > 10:
            # Filtrer les fausses pages 200 (souvent la home)
            if len(resp.content) < 500 or self.is_interesting(resp.content) or \
               any(x in url.lower() for x in [".env", ".sql", ".db", ".git", "backup", "config", "admin", "phpmyadmin"]):
                return True, url, len(resp.content)
        return False, url, 0

    # ---------- Port Scan ----------
    def scan_ports(self):
        if not self.target_domain:
            console.print("[red]Aucune cible[/]")
            return
        console.print(f"\n[yellow]🔌 Scan ports DB sur[/] {self.target_domain}...")
        open_ports = []
        for port, name in DB_PORTS.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if s.connect_ex((self.target_domain, port)) == 0:
                    open_ports.append({"port": port, "service": name})
                    console.print(f"  [green]✓[/] {port}/tcp — {name}")
                s.close()
            except Exception:
                pass
        self.results["open_ports"] = open_ports
        if not open_ports:
            console.print("  [dim]Aucun port DB ouvert détecté[/]")

    # ---------- Subdomains ----------
    def enum_subdomains(self):
        if not self.target_domain:
            return
        root = self.target_domain.split(":")[0]
        # Enlever www. si présent
        if root.startswith("www."):
            root = root[4:]
        console.print(f"\n[yellow]🌐 Subdomain enum[/] *.{root}...")
        found = []
        with ThreadPoolExecutor(max_workers=20) as pool:
            futs = {pool.submit(self._resolve, f"{sub}.{root}"): sub for sub in SUBDOMAIN_WORDLIST}
            for fut in as_completed(futs):
                sub = futs[fut]
                try:
                    ip = fut.result()
                    if ip:
                        full = f"{sub}.{root}"
                        found.append({"subdomain": full, "ip": ip})
                        console.print(f"  [green]✓[/] {full} → {ip}")
                except Exception:
                    pass
        self.results["subdomains"] = found
        console.print(f"[green]→ {len(found)} sous-domaines[/]")

    def _resolve(self, host: str) -> Optional[str]:
        try:
            return socket.gethostbyname(host)
        except Exception:
            return None

    # ---------- Wayback ----------
    def wayback(self):
        if not self.target_domain:
            return
        console.print(f"\n[yellow]⏪ Wayback Machine[/] {self.target_domain}...")
        try:
            cdx = f"https://web.archive.org/cdx/search/cdx?url=*.{self.target_domain}/*&output=json&fl=original&collapse=urlkey&limit=200"
            resp = requests.get(cdx, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                urls = list({row[0] for row in data[1:]}) if len(data) > 1 else []
                self.results["wayback_urls"] = urls[:150]
                console.print(f"  [green]→ {len(urls)} URLs historiques[/]")
                # Chercher des fichiers intéressants
                for u in urls:
                    if any(x in u.lower() for x in [".env", ".sql", ".db", "backup", "config", ".git"]):
                        console.print(f"  [magenta]  interesting:[/] {u}")
            else:
                console.print("  [dim]Pas de données Wayback[/]")
        except Exception as e:
            console.print(f"  [red]Erreur Wayback : {e}[/]")

    # ---------- DB Analysis ----------
    def _analyze_db(self, filepath: str, real_type: str, filename: str):
        analysis = {"file": filename, "type": real_type, "tables": {}, "error": None}
        try:
            if real_type == "sqlite":
                analysis = self._analyze_sqlite(filepath, filename)
            elif real_type in ("mysql_dump", "postgres_dump", "sql_dump"):
                analysis = self._analyze_sql_dump(filepath, filename)
            elif real_type == "gzip":
                with gzip.open(filepath, "rb") as f:
                    data = f.read()
                tmp = filepath + ".decomp"
                Path(tmp).write_bytes(data)
                t = self.identify_type(data)
                if t == "sqlite":
                    analysis = self._analyze_sqlite(tmp, filename)
                else:
                    analysis = self._analyze_sql_dump(tmp, filename)
                Path(tmp).unlink(missing_ok=True)
        except Exception as e:
            analysis["error"] = str(e)
        with self.lock:
            self.results["db_contents"][filename] = analysis
        self._print_db_summary(analysis)

    def _analyze_sqlite(self, path: str, name: str) -> dict:
        res = {"file": name, "type": "SQLite", "tables": {}, "error": None}
        try:
            tmp = f"/tmp/jathniel_{hashlib.md5(path.encode()).hexdigest()[:8]}.db"
            shutil.copy2(path, tmp)
            conn = sqlite3.connect(tmp)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            for (table,) in cur.fetchall():
                try:
                    cur.execute(f'SELECT COUNT(*) FROM "{table}"')
                    cnt = cur.fetchone()[0]
                    cur.execute(f'SELECT * FROM "{table}" LIMIT 5')
                    rows = cur.fetchall()
                    cols = [d[0] for d in cur.description] if cur.description else []
                    res["tables"][table] = {"columns": cols, "row_count": cnt, "sample": [list(r) for r in rows]}
                except Exception as e:
                    res["tables"][table] = {"error": str(e)}
            conn.close()
            Path(tmp).unlink(missing_ok=True)
        except Exception as e:
            res["error"] = str(e)
        return res

    def _analyze_sql_dump(self, path: str, name: str) -> dict:
        res = {"file": name, "type": "SQL Dump", "tables": {}, "error": None}
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
            tables = re.findall(r"CREATE TABLE\s+(?:IF NOT EXISTS\s+)?[`\"\[]?(\w+)[`\"\]]?", text, re.I)
            for t in tables:
                inserts = re.findall(rf"INSERT INTO\s+[`\"\[]?{re.escape(t)}[`\"\]]?.*?;", text, re.I | re.S)
                res["tables"][t] = {"insert_count": len(inserts), "sample": [i[:200] for i in inserts[:3]]}
        except Exception as e:
            res["error"] = str(e)
        return res

    def _print_db_summary(self, a: dict):
        console.print(f"    [cyan]└─ {a.get('type')} — {len(a.get('tables', {}))} tables[/]")
        for t, d in list(a.get("tables", {}).items())[:6]:
            if "error" in d:
                console.print(f"       • {t}: erreur")
            else:
                n = d.get("row_count") or d.get("insert_count", 0)
                console.print(f"       • {t}: {n} lignes")

    def _post_analysis(self):
        # Admin patterns rapides
        for p in ["/admin", "/administrator", "/login", "/wp-admin", "/phpmyadmin"]:
            url = f"{self.base_scheme}://{self.target_domain}{p}"
            resp = self._get(url, timeout=5)
            if resp and resp.status_code in (200, 301, 302, 401, 403):
                self.results["admin"].append(url)

    # ---------- Affichage / Export ----------
    def show_results(self):
        t = Table(title="Résultats", box=box.ROUNDED)
        t.add_column("Métrique", style="cyan")
        t.add_column("Valeur", style="green")
        t.add_row("Pages", str(self.results["stats"]["pages"]))
        t.add_row("Fichiers sensibles", str(self.results["stats"]["sensitive"]))
        t.add_row("Bases de données", str(self.results["stats"]["databases"]))
        t.add_row("Forced hits", str(len(self.results["forced_hits"])))
        t.add_row("Sous-domaines", str(len(self.results["subdomains"])))
        t.add_row("Ports ouverts", str(len(self.results["open_ports"])))
        t.add_row("Wayback URLs", str(len(self.results["wayback_urls"])))
        t.add_row("Emails", str(len(self.results["emails"])))
        t.add_row("Technologies", ", ".join(self.results["techs"]) or "—")
        console.print(t)

        if self.results["sensitive"]:
            console.print("\n[red]Fichiers sensibles :[/]")
            for s in self.results["sensitive"][:20]:
                console.print(f"  • {s['filename']} ← {s['url']}")

        if self.results["open_ports"]:
            console.print("\n[yellow]Ports ouverts :[/]")
            for p in self.results["open_ports"]:
                console.print(f"  • {p['port']}/tcp — {p['service']}")

        if self.results["subdomains"]:
            console.print("\n[cyan]Sous-domaines :[/]")
            for s in self.results["subdomains"][:15]:
                console.print(f"  • {s['subdomain']} → {s['ip']}")

    def show_databases(self):
        if not self.results["databases"]:
            console.print("[yellow]Aucune base trouvée[/]")
            return
        for db in self.results["databases"]:
            console.print(Panel(
                f"[bold]{db['filename']}[/] ({db['size']} o)\n"
                f"Type : {db.get('real_type')}\nURL : {db['url']}\nPath : {db['path']}",
                title="🗄️ Database", border_style="magenta",
            ))
            analysis = self.results["db_contents"].get(db["filename"], {})
            for t, d in analysis.get("tables", {}).items():
                if "error" in d:
                    continue
                cols = d.get("columns", [])
                n = d.get("row_count") or d.get("insert_count", 0)
                console.print(f"  [green]{t}[/] — {n} lignes — cols: {', '.join(cols[:8])}")

    def export(self):
        if not self.target_domain:
            console.print("[red]Rien à exporter[/]")
            return
        out = Path(self.config["output_dir"]) / self.target_domain / "reports"
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # JSON
        data = {
            "target": self.target_url,
            "stats": self.results["stats"],
            "sensitive": self.results["sensitive"],
            "databases": self.results["databases"],
            "db_contents": self.results["db_contents"],
            "forced_hits": self.results["forced_hits"],
            "subdomains": self.results["subdomains"],
            "open_ports": self.results["open_ports"],
            "wayback": self.results["wayback_urls"][:100],
            "emails": list(self.results["emails"]),
            "techs": list(self.results["techs"]),
            "admin": self.results["admin"],
        }
        # Convert datetime
        for k in ("start", "end"):
            if data["stats"].get(k):
                data["stats"][k] = str(data["stats"][k])

        jpath = out / f"report_{ts}.json"
        jpath.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]JSON → {jpath}[/]")

        # HTML simple
        hpath = out / f"report_{ts}.html"
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Report {self.target_domain}</title>
<style>body{{font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}}
h1,h2{{color:#58a6ff}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #30363d;padding:8px}}
th{{background:#161b22}}a{{color:#58a6ff}}</style></head><body>
<h1>JATHNIEL Crawler Report — {self.target_domain}</h1>
<p>Date: {ts}</p>
<h2>Stats</h2>
<ul>
<li>Pages: {self.results['stats']['pages']}</li>
<li>Sensibles: {self.results['stats']['sensitive']}</li>
<li>DB: {self.results['stats']['databases']}</li>
<li>Forced hits: {len(self.results['forced_hits'])}</li>
<li>Subdomains: {len(self.results['subdomains'])}</li>
<li>Open ports: {len(self.results['open_ports'])}</li>
</ul>
<h2>Sensitive files</h2><ul>"""
        for s in self.results["sensitive"]:
            html += f'<li><a href="{s["url"]}">{s["filename"]}</a> ({s["size"]} o)</li>'
        html += "</ul><h2>Databases</h2><ul>"
        for d in self.results["databases"]:
            html += f'<li><a href="{d["url"]}">{d["filename"]}</a> — {d.get("real_type")}</li>'
        html += "</ul></body></html>"
        hpath.write_text(html, encoding="utf-8")
        console.print(f"[green]HTML → {hpath}[/]")

    def show_config(self):
        t = Table(title="Configuration", box=box.ROUNDED)
        t.add_column("Clé", style="cyan")
        t.add_column("Valeur", style="green")
        for k, v in self.config.items():
            t.add_row(k, str(v))
        console.print(t)

    # ---------- Main loop ----------
    def run(self):
        while True:
            console.clear()
            self.banner()
            self.menu()
            choice = Prompt.ask("\n[bold yellow]Choix[/]", choices=[str(i) for i in range(11)], default="0")

            if choice == "0":
                console.print("[green]Bye![/]")
                break
            elif choice == "1":
                url = Prompt.ask("URL cible", default="https://example.com")
                self.crawl(url, full=False)
                Prompt.ask("\nEntrée pour continuer")
            elif choice == "2":
                url = Prompt.ask("URL cible", default="https://example.com")
                self.crawl(url, full=True)
                Prompt.ask("\nEntrée pour continuer")
            elif choice == "3":
                if not self.target_url:
                    self.target_url = Prompt.ask("URL cible")
                    self.target_domain = urlparse(self.target_url).netloc
                    self.base_scheme = urlparse(self.target_url).scheme or "https"
                self.forced_browsing()
                Prompt.ask("\nEntrée pour continuer")
            elif choice == "4":
                if not self.target_domain:
                    self.target_domain = Prompt.ask("Domaine")
                self.scan_ports()
                Prompt.ask("\nEntrée pour continuer")
            elif choice == "5":
                if not self.target_domain:
                    self.target_domain = Prompt.ask("Domaine")
                self.enum_subdomains()
                Prompt.ask("\nEntrée pour continuer")
            elif choice == "6":
                if not self.target_domain:
                    self.target_domain = Prompt.ask("Domaine")
                self.wayback()
                Prompt.ask("\nEntrée pour continuer")
            elif choice == "7":
                self.show_results()
                Prompt.ask("\nEntrée pour continuer")
            elif choice == "8":
                self.show_databases()
                Prompt.ask("\nEntrée pour continuer")
            elif choice == "9":
                self.export()
                Prompt.ask("\nEntrée pour continuer")
            elif choice == "10":
                self.show_config()
                Prompt.ask("\nEntrée pour continuer")


if __name__ == "__main__":
    try:
        CrawlerPro().run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrompu[/]")
        sys.exit(0)