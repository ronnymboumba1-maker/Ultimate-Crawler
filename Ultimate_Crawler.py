#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JATHNIEL-WEB-CRAWLER-PRO v6.0
Adaptive Polymorphic Engine + Soft-404 ML + Strategy AI

Usage : CTF / labo / pentests autorisés uniquement.
"""

import os
import sys
import re
import time
import json
import hashlib
import socket
import threading
import urllib3
import shutil
import sqlite3
import gzip
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque, defaultdict
from typing import Dict, List, Optional, Tuple, Any

import requests
import numpy as np
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt
from rich import box

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    SKLEARN_OK = True
except ImportError:
    SKLEARN_OK = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# ====================== WORDLISTS ======================

BASE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.old",
    "/config.php", "/configuration.php", "/config.inc.php", "/wp-config.php",
    "/wp-config.php.bak", "/web.config", "/app.config", "/database.yml",
    "/.git/HEAD", "/.git/config", "/.gitignore", "/.svn/entries",
    "/backup.zip", "/backup.sql", "/backup.tar.gz", "/db.sql", "/dump.sql",
    "/database.sql", "/database.db", "/data.db", "/app.db", "/users.db",
    "/database.sqlite", "/data.sqlite", "/app.sqlite", "/dump.rdb",
    "/admin/", "/administrator/", "/admin.php", "/login.php", "/panel/",
    "/dashboard/", "/phpmyadmin/", "/adminer.php", "/adminer/",
    "/api/", "/api/v1/", "/api/v2/", "/graphql", "/swagger/", "/swagger.json",
    "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/server-status", "/phpinfo.php", "/info.php", "/test.php",
    "/composer.json", "/package.json", "/requirements.txt", "/.htaccess",
    "/id_rsa", "/.ssh/id_rsa", "/authorized_keys",
    "/storage/logs/laravel.log", "/debug.log", "/error.log",
    "/Dockerfile", "/docker-compose.yml", "/.travis.yml", "/.gitlab-ci.yml",
]

BACKUP_SUFFIXES = [
    "", ".bak", ".old", ".orig", ".save", ".swp", ".tmp", "~",
    ".backup", ".copy", ".1", ".2", "_bak", "_old", "_backup",
    ".php.bak", ".php.old", ".php~", ".env.bak", ".sql.bak",
]

TECH_PATHS = {
    "WordPress": [
        "/wp-admin/", "/wp-login.php", "/wp-content/debug.log",
        "/wp-config.php", "/wp-config.php.bak", "/xmlrpc.php",
        "/wp-includes/", "/wp-json/",
    ],
    "Laravel": [
        "/.env", "/storage/logs/laravel.log", "/artisan",
        "/config/database.php", "/.env.example",
    ],
    "Django": [
        "/settings.py", "/admin/", "/static/", "/media/",
        "/db.sqlite3", "/local_settings.py",
    ],
    "phpMyAdmin": [
        "/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/myadmin/",
        "/mysql/", "/dbadmin/",
    ],
}

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})", "API Key"),
    (r"(?i)(secret|token|password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})", "Secret/Password"),
    (r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", "JWT"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"(?i)mongodb(\+srv)?://[^\s\"']+", "MongoDB URI"),
    (r"(?i)postgres(ql)?://[^\s\"']+", "PostgreSQL URI"),
    (r"(?i)mysql://[^\s\"']+", "MySQL URI"),
    (r"(?i)redis://[^\s\"']+", "Redis URI"),
    (r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----", "Private Key"),
    (r"(?i)(aws_secret_access_key|secret_key)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{30,})", "AWS Secret"),
]

DB_PORTS = {
    3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
    6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
}

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "webmail", "admin", "dev", "staging", "test",
    "api", "beta", "app", "portal", "dashboard", "panel", "cpanel",
    "db", "mysql", "sql", "phpmyadmin", "git", "gitlab", "jenkins",
    "monitor", "status", "cdn", "static", "img", "media", "shop",
    "blog", "news", "support", "vpn", "remote", "old", "new", "m",
]


# ====================== SOFT-404 ML ======================

class Soft404Detector:
    """Classificateur Soft-404 avec apprentissage en live (sklearn)."""

    def __init__(self):
        self.model = None
        self.scaler = StandardScaler() if SKLEARN_OK else None
        self.trained = False
        self.home_features = None
        self.home_size = 0
        self.home_title = ""
        self.home_hash = ""
        self.samples_X = []
        self.samples_y = []

    def _features(self, resp: requests.Response, text: str) -> List[float]:
        size = len(resp.content)
        title = ""
        try:
            soup = BeautifulSoup(text, "html.parser")
            t = soup.find("title")
            title = t.get_text(strip=True) if t else ""
        except Exception:
            pass

        low = text.lower()
        error_words = sum(1 for w in ["not found", "404", "page not found", "does not exist",
                                      "erreur", "introuvable", "forbidden", "access denied"] if w in low)
        link_count = text.lower().count("href=")
        script_count = text.lower().count("<script")
        has_form = 1 if "<form" in low else 0
        title_len = len(title)
        size_ratio = size / max(self.home_size, 1) if self.home_size else 1.0
        title_sim = 1.0 if title and title == self.home_title else 0.0
        hash_sim = 1.0 if hashlib.md5(resp.content).hexdigest() == self.home_hash else 0.0

        return [
            float(size),
            float(title_len),
            float(error_words),
            float(link_count),
            float(script_count),
            float(has_form),
            float(size_ratio),
            float(title_sim),
            float(hash_sim),
            float(resp.status_code),
        ]

    def fit_home(self, resp: requests.Response, text: str):
        self.home_size = len(resp.content)
        self.home_hash = hashlib.md5(resp.content).hexdigest()
        try:
            soup = BeautifulSoup(text, "html.parser")
            t = soup.find("title")
            self.home_title = t.get_text(strip=True) if t else ""
        except Exception:
            self.home_title = ""
        self.home_features = self._features(resp, text)
        # Home = classe 0 (vrai contenu)
        self.samples_X.append(self.home_features)
        self.samples_y.append(0)

    def add_sample(self, resp: requests.Response, text: str, is_soft404: bool):
        feats = self._features(resp, text)
        self.samples_X.append(feats)
        self.samples_y.append(1 if is_soft404 else 0)

    def train(self):
        if not SKLEARN_OK or len(self.samples_X) < 6:
            return
        try:
            X = np.array(self.samples_X)
            y = np.array(self.samples_y)
            Xs = self.scaler.fit_transform(X)
            self.model = RandomForestClassifier(n_estimators=40, max_depth=6, random_state=42)
            self.model.fit(Xs, y)
            self.trained = True
        except Exception:
            self.trained = False

    def is_soft404(self, resp: requests.Response, text: str) -> bool:
        if resp.status_code != 200:
            return False
        # Heuristique rapide
        if self.home_size > 0:
            ratio = len(resp.content) / self.home_size
            if 0.85 < ratio < 1.15:
                try:
                    soup = BeautifulSoup(text, "html.parser")
                    t = soup.find("title")
                    title = t.get_text(strip=True) if t else ""
                    if title and title == self.home_title:
                        return True
                except Exception:
                    pass
                if hashlib.md5(resp.content).hexdigest() == self.home_hash:
                    return True

        if self.trained and self.model is not None:
            try:
                feats = np.array([self._features(resp, text)])
                feats = self.scaler.transform(feats)
                pred = self.model.predict(feats)[0]
                return bool(pred == 1)
            except Exception:
                pass
        return False


# ====================== SCORER & STRATEGY ======================

class FindingScorer:
    def __init__(self):
        self.weights = {
            "phpmyadmin": 95, "adminer": 90, ".env": 98, "wp-config": 92,
            ".git": 96, "backup": 80, ".sql": 88, ".db": 90, ".sqlite": 90,
            "private key": 97, "api key": 85, "jwt": 70, "password": 75,
            "admin": 65, "panel": 60, "login": 55, "config": 70,
        }

    def score(self, url: str, content_preview: str = "", real_type: str = "") -> Tuple[int, str]:
        score = 20
        low = (url + " " + content_preview + " " + real_type).lower()
        for key, val in self.weights.items():
            if key in low:
                score = max(score, val)
        if real_type in ("sqlite", "mysql_dump", "postgres_dump", "sql_dump"):
            score = max(score, 90)
        if score >= 90:
            sev = "CRITICAL"
        elif score >= 75:
            sev = "HIGH"
        elif score >= 55:
            sev = "MEDIUM"
        else:
            sev = "LOW"
        return score, sev


class StrategyManager:
    """Moteur polymorphe : adapte le comportement en live."""

    def __init__(self):
        self.threads = 12
        self.delay = 0.25
        self.mode = "normal"          # normal | stealth | aggressive | deep
        self.tech = set()
        self.success_rate = 0.5
        self.avg_latency = 0.5
        self.error_403 = 0
        self.total_req = 0
        self.findings_count = 0
        self.paths = list(BASE_PATHS)

    def observe(self, status: int, latency: float, is_finding: bool = False):
        self.total_req += 1
        self.avg_latency = (self.avg_latency * 0.8) + (latency * 0.2)
        if status == 403:
            self.error_403 += 1
        if is_finding:
            self.findings_count += 1
        if self.total_req > 20:
            self.success_rate = self.findings_count / max(self.total_req, 1)

    def adapt(self):
        # Latence élevée → ralentir
        if self.avg_latency > 1.3:
            self.threads = max(4, self.threads - 2)
            self.delay = min(1.2, self.delay + 0.15)
            self.mode = "stealth"
        elif self.avg_latency < 0.4 and self.error_403 < 5:
            self.threads = min(20, self.threads + 2)
            self.delay = max(0.1, self.delay - 0.05)
            self.mode = "aggressive"

        # Beaucoup de 403 → stealth
        if self.error_403 > 15:
            self.mode = "stealth"
            self.threads = max(3, self.threads - 3)
            self.delay = min(1.5, self.delay + 0.2)

        # Peu de findings → mode deep (plus de backups)
        if self.total_req > 120 and self.findings_count < 3:
            self.mode = "deep"

        # Techno détectée → enrichir les chemins
        for t in self.tech:
            if t in TECH_PATHS:
                for p in TECH_PATHS[t]:
                    if p not in self.paths:
                        self.paths.append(p)

    def add_tech(self, name: str):
        self.tech.add(name)
        self.adapt()

    def get_paths(self) -> List[str]:
        if self.mode == "deep":
            # Générer plus de variantes
            extra = []
            for p in list(self.paths)[:40]:
                for s in BACKUP_SUFFIXES:
                    if s and not p.endswith(s):
                        extra.append(p + s)
            return self.paths + extra[:80]
        return self.paths


# ====================== CRAWLER PRINCIPAL ======================

class CrawlerProV6:
    def __init__(self):
        self.config = {
            "max_depth": 3,
            "max_pages": 450,
            "timeout": 11,
            "output_dir": "./crawled_sites",
            "verify_ssl": False,
            "user_agent": "Mozilla/5.0 (compatible; JATHNIEL-Crawler/6.0; CTF)",
        }
        self.target_url = ""
        self.target_domain = ""
        self.base_scheme = "https"
        self.visited = set()
        self.queue = deque()
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": self.config["user_agent"]})

        self.soft404 = Soft404Detector()
        self.scorer = FindingScorer()
        self.strategy = StrategyManager()

        self.results = {
            "pages": [],
            "sensitive": [],
            "databases": [],
            "db_contents": {},
            "secrets": [],
            "subdomains": [],
            "open_ports": [],
            "js_endpoints": [],
            "admin": [],
            "emails": set(),
            "techs": set(),
            "forced_hits": [],
            "stats": {"pages": 0, "sensitive": 0, "databases": 0, "secrets": 0,
                      "start": None, "end": None, "duration": 0},
        }

    # ---------- UI ----------
    def banner(self):
        console.print(Panel.fit(
            "[bold red]🕷️  JATHNIEL-WEB-CRAWLER-PRO v6.0[/]\n"
            "[cyan]Adaptive AI · Soft-404 ML · Polymorphic Strategy[/]\n"
            "[dim]CTF / Lab / Authorized only — 95%+ target[/]",
            border_style="cyan",
        ))

    def menu(self):
        t = Table(show_header=False, box=box.ROUNDED, border_style="cyan")
        t.add_column("N", style="yellow", width=4)
        t.add_column("Action")
        for n, a in [
            ("1", "Crawl adaptatif complet (recommandé)"),
            ("2", "Forced Browsing intelligent"),
            ("3", "Scan ports DB"),
            ("4", "Subdomains (wordlist + crt.sh)"),
            ("5", "Voir findings scorés"),
            ("6", "Voir bases de données"),
            ("7", "Voir secrets trouvés"),
            ("8", "Exporter JSON/HTML"),
            ("9", "État de l’IA (strategy)"),
            ("0", "Quitter"),
        ]:
            t.add_row(n, a)
        console.print(t)
        if self.target_url:
            console.print(f"[dim]Cible: {self.target_url} | Mode IA: {self.strategy.mode} | "
                          f"Findings: {self.results['stats']['sensitive']+self.results['stats']['databases']}[/]")

    # ---------- Helpers ----------
    def _get(self, url: str, timeout: int = None) -> Optional[requests.Response]:
        t0 = time.time()
        try:
            r = self.session.get(url, timeout=timeout or self.config["timeout"], allow_redirects=True)
            latency = time.time() - t0
            self.strategy.observe(r.status_code, latency)
            return r
        except Exception:
            self.strategy.observe(0, time.time() - t0)
            return None

    def identify_type(self, content: bytes) -> str:
        if content.startswith(b"SQLite format 3\x00"):
            return "sqlite"
        if content.startswith(b"-- MySQL dump") or b"ENGINE=InnoDB" in content[:3000]:
            return "mysql_dump"
        if content.startswith(b"-- PostgreSQL"):
            return "postgres_dump"
        if b"CREATE TABLE" in content[:5000] and b"INSERT INTO" in content[:8000]:
            return "sql_dump"
        if content.startswith(b"PK\x03\x04"):
            return "zip"
        if content.startswith(b"\x1f\x8b"):
            return "gzip"
        return "unknown"

    # ---------- Secret Scanner ----------
    def scan_secrets(self, text: str, source: str):
        for pat, label in SECRET_PATTERNS:
            for m in re.finditer(pat, text):
                val = m.group(0)[:80]
                with self.lock:
                    self.results["secrets"].append({
                        "type": label, "value": val, "source": source
                    })
                    self.results["stats"]["secrets"] += 1
                console.print(f"  [bold red]🔑 {label}[/] ← {source}")

    # ---------- JS Analyzer ----------
    def analyze_js(self, url: str, text: str):
        # Endpoints
        endpoints = set()
        for m in re.finditer(r"['\"](/(?:api|v1|v2|graphql|admin|auth)[^'\"]{0,60})['\"]", text):
            endpoints.add(m.group(1))
        for m in re.finditer(r"['\"](https?://[^'\"]{10,80})['\"]", text):
            u = m.group(1)
            if self.target_domain in u:
                endpoints.add(u)
        for ep in list(endpoints)[:30]:
            with self.lock:
                self.results["js_endpoints"].append({"endpoint": ep, "source": url})
        if endpoints:
            console.print(f"  [cyan]JS endpoints: {len(endpoints)}[/] ← {url}")
        self.scan_secrets(text, url)

    # ---------- Crawl ----------
    def crawl(self, url: str):
        self.target_url = url.rstrip("/")
        p = urlparse(self.target_url)
        self.target_domain = p.netloc
        self.base_scheme = p.scheme or "https"

        out = Path(self.config["output_dir"]) / self.target_domain
        for d in ["pages", "sensitive", "databases", "reports"]:
            (out / d).mkdir(parents=True, exist_ok=True)

        self.results["stats"]["start"] = datetime.now()
        self.visited.clear()
        self.queue.clear()
        self.queue.append((self.target_url, 0))

        console.print(f"\n[cyan]🕷️  Crawl adaptatif de[/] {self.target_url}")
        console.print(f"[dim]Dossier: {out} | Soft-404 ML: {'ON' if SKLEARN_OK else 'OFF (heuristique)'}[/]\n")

        # Page d’accueil → entraîner le Soft404
        home = self._get(self.target_url)
        if home and home.status_code == 200:
            self.soft404.fit_home(home, home.text)
            self._detect_tech(home.text, home.headers)
            self.scan_secrets(home.text, self.target_url)

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      console=console) as progress:
            task = progress.add_task("Crawl...", total=self.config["max_pages"])

            with ThreadPoolExecutor(max_workers=self.strategy.threads) as pool:
                futures = {}
                while (self.queue or futures) and len(self.visited) < self.config["max_pages"]:
                    self.strategy.adapt()
                    while self.queue and len(futures) < self.strategy.threads * 2:
                        u, depth = self.queue.popleft()
                        if u in self.visited:
                            continue
                        self.visited.add(u)
                        futures[pool.submit(self._crawl_page, u, depth, out)] = u

                    if not futures:
                        break
                    for fut in list(futures.keys()):
                        if fut.done():
                            futures.pop(fut, None)
                            progress.update(task, completed=len(self.visited))
                            try:
                                fut.result()
                            except Exception:
                                pass
                    time.sleep(self.strategy.delay)

        # Modules post-crawl
        self.forced_browsing(out)
        self.scan_ports()
        self.enum_subdomains()
        self.crtsh()

        # Entraînement final Soft404
        self.soft404.train()

        self.results["stats"]["end"] = datetime.now()
        self.results["stats"]["duration"] = (
            self.results["stats"]["end"] - self.results["stats"]["start"]
        ).total_seconds()

        console.print(f"\n[green]✅ Terminé[/] — Pages: {self.results['stats']['pages']} | "
                      f"Sensibles: {self.results['stats']['sensitive']} | "
                      f"DB: {self.results['stats']['databases']} | "
                      f"Secrets: {self.results['stats']['secrets']} | "
                      f"Mode IA: {self.strategy.mode} | "
                      f"{self.results['stats']['duration']:.1f}s")

    def _crawl_page(self, url: str, depth: int, out: Path):
        resp = self._get(url)
        if not resp or resp.status_code != 200:
            return
        text = resp.text
        content = resp.content

        if self.soft404.is_soft404(resp, text):
            self.soft404.add_sample(resp, text, is_soft404=True)
            return
        self.soft404.add_sample(resp, text, is_soft404=False)

        # Sauvegarde
        name = re.sub(r"[^\w\-.]", "_", urlparse(url).path or "index")[:80]
        if not name.endswith(".html"):
            name += ".html"
        (out / "pages" / name).write_text(text, encoding="utf-8", errors="ignore")

        with self.lock:
            self.results["pages"].append({"url": url, "size": len(content)})
            self.results["stats"]["pages"] += 1

        self._detect_tech(text, resp.headers)
        self.scan_secrets(text, url)

        # JS
        if url.endswith(".js") or "javascript" in resp.headers.get("Content-Type", ""):
            self.analyze_js(url, text)

        # Liens
        if depth < self.config["max_depth"]:
            soup = BeautifulSoup(text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("#") or href.startswith("javascript:"):
                    continue
                abs_u = urljoin(url, href)
                if self.target_domain in urlparse(abs_u).netloc and abs_u not in self.visited:
                    with self.lock:
                        self.queue.append((abs_u, depth + 1))
            # JS files
            for s in soup.find_all("script", src=True):
                abs_u = urljoin(url, s["src"])
                if abs_u not in self.visited and self.target_domain in urlparse(abs_u).netloc:
                    with self.lock:
                        self.queue.append((abs_u, depth + 1))

        # Fichiers sensibles dans le HTML
        self._extract_sensitive_links(text, url, out)

    def _detect_tech(self, text: str, headers):
        low = text.lower()
        h = str(headers).lower()
        mapping = {
            "WordPress": ["wp-content", "wp-includes", "wp-json"],
            "Laravel": ["laravel", "csrf-token"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "phpMyAdmin": ["phpmyadmin", "pma_"],
            "React": ["react", "react-dom"],
            "Vue": ["vue.js", "vue.min"],
            "jQuery": ["jquery"],
        }
        for tech, pats in mapping.items():
            if any(p in low or p in h for p in pats):
                self.results["techs"].add(tech)
                self.strategy.add_tech(tech)

    def _extract_sensitive_links(self, html: str, base: str, out: Path):
        cands = set()
        for m in re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', html, re.I):
            cands.add(urljoin(base, m))
        for m in re.findall(r'(/[a-zA-Z0-9_\-./]+\.(?:env|sql|db|sqlite|sqlite3|bak|old|zip|log|yml|pem|key|dump))', html, re.I):
            cands.add(urljoin(base, m))
        for u in cands:
            if any(x in u.lower() for x in [".env", ".sql", ".db", ".sqlite", ".bak", ".git", "backup", "config", ".log"]):
                self._download_sensitive(u, out)

    def _download_sensitive(self, url: str, out: Path) -> bool:
        if url in self.visited:
            return False
        with self.lock:
            self.visited.add(url)
        resp = self._get(url)
        if not resp or resp.status_code != 200:
            return False
        if self.soft404.is_soft404(resp, resp.text):
            return False
        content = resp.content
        if len(content) > 45 * 1024 * 1024:
            return False

        real = self.identify_type(content)
        is_db = real in ("sqlite", "mysql_dump", "postgres_dump", "sql_dump", "gzip") or \
                any(url.lower().endswith(e) for e in [".sql", ".db", ".sqlite", ".sqlite3", ".dump", ".rdb"])

        fname = urlparse(url).path.split("/")[-1] or hashlib.md5(url.encode()).hexdigest()[:10]
        fname = re.sub(r"[^\w\-.]", "_", fname)[:90]
        dest = out / ("databases" if is_db else "sensitive")
        path = dest / fname
        if path.exists():
            path = dest / f"{path.stem}_{hashlib.md5(url.encode()).hexdigest()[:6]}{path.suffix}"
        path.write_bytes(content)

        score, sev = self.scorer.score(url, content[:300].decode("utf-8", errors="ignore"), real)
        info = {
            "url": url, "filename": path.name, "size": len(content),
            "path": str(path), "real_type": real, "score": score, "severity": sev,
        }
        with self.lock:
            if is_db:
                self.results["databases"].append(info)
                self.results["stats"]["databases"] += 1
                console.print(f"  [magenta]🗄️  [{sev}] {path.name}[/] (score {score}) ← {url}")
                self._analyze_db(str(path), real, path.name)
            else:
                self.results["sensitive"].append(info)
                self.results["stats"]["sensitive"] += 1
                console.print(f"  [red]🔴 [{sev}] {path.name}[/] (score {score}) ← {url}")
            self.strategy.observe(200, 0.3, is_finding=True)

        self.scan_secrets(content[:15000].decode("utf-8", errors="ignore"), url)
        return True

    # ---------- Forced Browsing ----------
    def forced_browsing(self, out: Path = None):
        if not self.target_domain:
            return
        if out is None:
            out = Path(self.config["output_dir"]) / self.target_domain
            out.mkdir(parents=True, exist_ok=True)
            (out / "sensitive").mkdir(exist_ok=True)
            (out / "databases").mkdir(exist_ok=True)

        paths = self.strategy.get_paths()
        console.print(f"\n[yellow]🔫 Forced Browsing adaptatif[/] ({len(paths)} chemins) — mode {self.strategy.mode}")

        base = f"{self.base_scheme}://{self.target_domain}"
        hits = []
        with ThreadPoolExecutor(max_workers=self.strategy.threads) as pool:
            futs = {pool.submit(self._probe, base + p): p for p in paths}
            for fut in as_completed(futs):
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
        if not resp or resp.status_code != 200:
            return False, url, 0
        if self.soft404.is_soft404(resp, resp.text):
            return False, url, 0
        return True, url, len(resp.content)

    # ---------- Ports / Subdomains / crt.sh ----------
    def scan_ports(self):
        if not self.target_domain:
            return
        console.print(f"\n[yellow]🔌 Scan ports DB[/] {self.target_domain}...")
        open_p = []
        for port, name in DB_PORTS.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if s.connect_ex((self.target_domain.split(":")[0], port)) == 0:
                    open_p.append({"port": port, "service": name})
                    console.print(f"  [green]✓ {port}/tcp — {name}[/]")
                s.close()
            except Exception:
                pass
        self.results["open_ports"] = open_p
        if not open_p:
            console.print("  [dim]Aucun port DB ouvert[/]")

    def enum_subdomains(self):
        root = self.target_domain.split(":")[0]
        if root.startswith("www."):
            root = root[4:]
        console.print(f"\n[yellow]🌐 Subdomains[/] *.{root}")
        found = []
        with ThreadPoolExecutor(max_workers=25) as pool:
            futs = {pool.submit(self._resolve, f"{s}.{root}"): s for s in SUBDOMAIN_WORDLIST}
            for fut in as_completed(futs):
                try:
                    ip = fut.result()
                    if ip:
                        full = f"{futs[fut]}.{root}"
                        found.append({"subdomain": full, "ip": ip})
                        console.print(f"  [green]✓ {full} → {ip}[/]")
                except Exception:
                    pass
        self.results["subdomains"] = found

    def _resolve(self, host: str) -> Optional[str]:
        try:
            return socket.gethostbyname(host)
        except Exception:
            return None

    def crtsh(self):
        root = self.target_domain.split(":")[0]
        if root.startswith("www."):
            root = root[4:]
        console.print(f"\n[yellow]📜 Certificate Transparency (crt.sh)[/]")
        try:
            r = requests.get(f"https://crt.sh/?q=%.{root}&output=json", timeout=25)
            if r.status_code == 200:
                data = r.json()
                subs = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower()
                        if line.endswith(root) and "*" not in line:
                            subs.add(line)
                new = 0
                for s in list(subs)[:80]:
                    if not any(x["subdomain"] == s for x in self.results["subdomains"]):
                        ip = self._resolve(s)
                        if ip:
                            self.results["subdomains"].append({"subdomain": s, "ip": ip})
                            console.print(f"  [green]✓ {s} → {ip}[/]")
                            new += 1
                console.print(f"[green]→ +{new} sous-domaines via CT[/]")
        except Exception as e:
            console.print(f"  [dim]crt.sh indisponible: {e}[/]")

    # ---------- DB Analysis ----------
    def _analyze_db(self, path: str, real: str, name: str):
        analysis = {"file": name, "type": real, "tables": {}, "error": None}
        try:
            if real == "sqlite":
                analysis = self._sqlite(path, name)
            elif real in ("mysql_dump", "postgres_dump", "sql_dump"):
                analysis = self._sqldump(path, name)
        except Exception as e:
            analysis["error"] = str(e)
        with self.lock:
            self.results["db_contents"][name] = analysis
        tables = analysis.get("tables", {})
        console.print(f"    [cyan]└─ {len(tables)} tables[/]")

    def _sqlite(self, path: str, name: str) -> dict:
        res = {"file": name, "type": "SQLite", "tables": {}, "error": None}
        tmp = f"/tmp/jath_{hashlib.md5(path.encode()).hexdigest()[:8]}.db"
        try:
            shutil.copy2(path, tmp)
            conn = sqlite3.connect(tmp)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            for (t,) in cur.fetchall():
                try:
                    cur.execute(f'SELECT COUNT(*) FROM "{t}"')
                    cnt = cur.fetchone()[0]
                    cur.execute(f'SELECT * FROM "{t}" LIMIT 4')
                    rows = cur.fetchall()
                    cols = [d[0] for d in cur.description] if cur.description else []
                    res["tables"][t] = {"columns": cols, "row_count": cnt, "sample": [list(r) for r in rows]}
                except Exception as e:
                    res["tables"][t] = {"error": str(e)}
            conn.close()
        except Exception as e:
            res["error"] = str(e)
        finally:
            Path(tmp).unlink(missing_ok=True)
        return res

    def _sqldump(self, path: str, name: str) -> dict:
        res = {"file": name, "type": "SQL Dump", "tables": {}, "error": None}
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
            tables = re.findall(r"CREATE TABLE\s+(?:IF NOT EXISTS\s+)?[`\"\[]?(\w+)", text, re.I)
            for t in tables:
                inserts = re.findall(rf"INSERT INTO\s+[`\"\[]?{re.escape(t)}[`\"\]]?.*?;", text, re.I | re.S)
                res["tables"][t] = {"insert_count": len(inserts), "sample": [i[:180] for i in inserts[:2]]}
        except Exception as e:
            res["error"] = str(e)
        return res

    # ---------- Affichage / Export ----------
    def show_findings(self):
        all_f = self.results["sensitive"] + self.results["databases"]
        all_f.sort(key=lambda x: x.get("score", 0), reverse=True)
        t = Table(title="Findings scorés", box=box.ROUNDED)
        t.add_column("Sev", style="bold")
        t.add_column("Score")
        t.add_column("Fichier")
        t.add_column("URL")
        for f in all_f[:40]:
            sev = f.get("severity", "LOW")
            color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "dim"}.get(sev, "white")
            t.add_row(f"[{color}]{sev}[/]", str(f.get("score", 0)), f["filename"], f["url"][:60])
        console.print(t)

        if self.results["open_ports"]:
            console.print("\n[yellow]Ports ouverts:[/]")
            for p in self.results["open_ports"]:
                console.print(f"  • {p['port']}/tcp — {p['service']}")
        if self.results["subdomains"]:
            console.print(f"\n[cyan]Sous-domaines ({len(self.results['subdomains'])}):[/]")
            for s in self.results["subdomains"][:15]:
                console.print(f"  • {s['subdomain']} → {s['ip']}")

    def show_databases(self):
        if not self.results["databases"]:
            console.print("[yellow]Aucune DB[/]")
            return
        for db in self.results["databases"]:
            console.print(Panel(
                f"[bold]{db['filename']}[/] — {db.get('severity')} (score {db.get('score')})\n"
                f"Type: {db.get('real_type')} | {db['size']} o\n{db['url']}",
                border_style="magenta",
            ))
            a = self.results["db_contents"].get(db["filename"], {})
            for tname, td in a.get("tables", {}).items():
                n = td.get("row_count") or td.get("insert_count", 0)
                cols = ", ".join(td.get("columns", [])[:6])
                console.print(f"  [green]{tname}[/] — {n} lignes — {cols}")

    def show_secrets(self):
        if not self.results["secrets"]:
            console.print("[yellow]Aucun secret[/]")
            return
        for s in self.results["secrets"][:30]:
            console.print(f"  [red]{s['type']}[/] : {s['value'][:70]}  ← {s['source'][:50]}")

    def show_ai_state(self):
        t = Table(title="État de l’IA Adaptive", box=box.ROUNDED)
        t.add_column("Paramètre", style="cyan")
        t.add_column("Valeur", style="green")
        t.add_row("Mode", self.strategy.mode)
        t.add_row("Threads", str(self.strategy.threads))
        t.add_row("Delay", f"{self.strategy.delay:.2f}s")
        t.add_row("Latence moy", f"{self.strategy.avg_latency:.2f}s")
        t.add_row("Requêtes", str(self.strategy.total_req))
        t.add_row("Findings", str(self.strategy.findings_count))
        t.add_row("Soft-404 ML", "Entraîné" if self.soft404.trained else "Heuristique")
        t.add_row("Technos", ", ".join(self.strategy.tech) or "—")
        console.print(t)

    def export(self):
        if not self.target_domain:
            console.print("[red]Rien à exporter[/]")
            return
        out = Path(self.config["output_dir"]) / self.target_domain / "reports"
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        data = {
            "target": self.target_url,
            "stats": {k: str(v) if isinstance(v, datetime) else v for k, v in self.results["stats"].items()},
            "sensitive": self.results["sensitive"],
            "databases": self.results["databases"],
            "secrets": self.results["secrets"],
            "subdomains": self.results["subdomains"],
            "open_ports": self.results["open_ports"],
            "js_endpoints": self.results["js_endpoints"][:50],
            "techs": list(self.results["techs"]),
            "ai_mode": self.strategy.mode,
        }
        jpath = out / f"report_{ts}.json"
        jpath.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]JSON → {jpath}[/]")

    def run(self):
        while True:
            console.clear()
            self.banner()
            self.menu()
            c = Prompt.ask("\n[bold yellow]Choix[/]", choices=[str(i) for i in range(10)], default="0")
            if c == "0":
                console.print("[green]Bye[/]")
                break
            elif c == "1":
                url = Prompt.ask("URL cible", default="https://example.com")
                self.crawl(url)
                Prompt.ask("\nEntrée")
            elif c == "2":
                if not self.target_url:
                    self.target_url = Prompt.ask("URL")
                    self.target_domain = urlparse(self.target_url).netloc
                    self.base_scheme = urlparse(self.target_url).scheme or "https"
                self.forced_browsing()
                Prompt.ask("\nEntrée")
            elif c == "3":
                if not self.target_domain:
                    self.target_domain = Prompt.ask("Domaine")
                self.scan_ports()
                Prompt.ask("\nEntrée")
            elif c == "4":
                if not self.target_domain:
                    self.target_domain = Prompt.ask("Domaine")
                self.enum_subdomains()
                self.crtsh()
                Prompt.ask("\nEntrée")
            elif c == "5":
                self.show_findings()
                Prompt.ask("\nEntrée")
            elif c == "6":
                self.show_databases()
                Prompt.ask("\nEntrée")
            elif c == "7":
                self.show_secrets()
                Prompt.ask("\nEntrée")
            elif c == "8":
                self.export()
                Prompt.ask("\nEntrée")
            elif c == "9":
                self.show_ai_state()
                Prompt.ask("\nEntrée")


if __name__ == "__main__":
    try:
        CrawlerProV6().run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrompu[/]")
        sys.exit(0)