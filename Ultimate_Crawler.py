#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
JATHNIEL-WEB-CRAWLER-PRO v4.0
Crawler web professionnel avec détection et extraction de bases de données exposées

Pour Ubuntu/WSL - Usage éducatif et tests de sécurité autorisés uniquement
(cadre CTF, labo personnel, DVWA, WebGoat, etc.)

NOUVEAUTÉS v4.0 :
[OK] Détection de bases de données exposées (SQLite, MySQL, PostgreSQL, MongoDB, Redis)
[OK] Identification par magic bytes (extension trompeuse gérée)
[OK] Ouverture automatique des SQLite + dump des tables
[OK] Parsing des dumps SQL (CREATE TABLE + INSERT)
[OK] Détection des liens DB dans le HTML
[OK] Rapport structuré avec tables, colonnes et échantillons
"""

import os
import sys
import time
import json
import re
import hashlib
import threading
import queue
import socket
import urllib3
import shutil
import sqlite3
import gzip
import bz2
import lzma
import zipfile
import tarfile
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from typing import Dict, List, Tuple, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque, defaultdict
from io import BytesIO

import requests
from bs4 import BeautifulSoup
import mimetypes

# Désactiver les avertissements SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class JATHNIELCrawlerPro:
    """Crawler web professionnel avec extraction de bases de données exposées."""
    
    def __init__(self):
        # Configuration
        self.config = {
            'max_depth': 3,
            'max_pages': 500,
            'max_files': 100,
            'threads': 10,
            'timeout': 30,
            'delay': 0.5,
            'user_agent': 'JATHNIEL-Crawler-Pro/4.0 (Educational; CTF/Lab)',
            'output_dir': './crawled_sites',
            'download_sensitive': True,
            'download_assets': True,
            'respect_robots': True,
            'javascript': False,
            'follow_redirects': True,
            'verify_ssl': False,
            'analyze_db': True,       # Analyse auto des DB trouvées
            'auto_extract_zip': True, # Extraction auto des archives
        }
        
        # État
        self.target_url = ""
        self.target_domain = ""
        self.visited_urls = set()
        self.visited_files = set()
        self.queue = deque()
        self.results = {
            'pages': [],
            'assets': [],
            'sensitive_files': [],
            'databases': [],       # Nouveau : bases trouvées
            'db_contents': {},     # Nouveau : contenu des DB
            'forms': [],
            'links': [],
            'emails': [],
            'technologies': [],
            'admin_pages': [],
            'comments': [],
            'vulnerabilities': [],
            'statistics': {
                'total_pages': 0,
                'total_assets': 0,
                'total_sensitive': 0,
                'total_databases': 0,
                'total_size': 0,
                'start_time': None,
                'end_time': None,
                'duration': 0
            }
        }
        
        self.lock = threading.Lock()
        self.scanning = False
        self.pause = False
        
        # ==================== LISTES SENSIBLES ====================
        
        # Extensions sensibles
        self.sensitive_extensions = [
            # Configuration
            '.env', '.env.local', '.env.prod', '.env.backup',
            '.ini', '.conf', '.config', '.cfg',
            '.yml', '.yaml', '.xml', '.json', '.toml',
            # Base de données
            '.sql', '.db', '.sqlite', '.sqlite3', '.db3', '.s3db',
            '.dump', '.bson', '.rdb', '.pgdump', '.archive',
            # Archives
            '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz',
            # Auth / certificats
            '.pem', '.crt', '.cer', '.key', '.p12', '.pfx', '.ppk',
            # Logs
            '.log',
            # Binaires suspects
            '.bin', '.dat', '.raw', '.img', '.iso',
        ]
        
        # Noms de fichiers sensibles
        self.sensitive_filenames = [
            # Config
            'wp-config.php', 'config.php', 'configuration.php',
            'settings.py', 'settings.json', 'appsettings.json',
            'web.config', 'app.config', 'database.yml', 'db.php',
            'config.inc.php', 'php.ini', 'nginx.conf', 'httpd.conf',
            # Discovery
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'humans.txt', 'security.txt', 'clientaccesspolicy.xml',
            # Auth / clés
            'passwd', 'shadow', 'sudoers',
            'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
            'authorized_keys', 'known_hosts',
            '.bash_history', '.bashrc', '.profile', '.gitconfig',
            '.gitignore', '.DS_Store', 'Thumbs.db', '.htaccess', '.htpasswd',
            # Dépendances
            'composer.json', 'composer.lock', 'package.json',
            'package-lock.json', 'yarn.lock', 'requirements.txt',
            'Gemfile', 'Gemfile.lock', 'pom.xml', 'build.gradle',
            # Docker / CI
            'Dockerfile', 'docker-compose.yml', 'Makefile', 'Vagrantfile',
            '.travis.yml', '.gitlab-ci.yml', 'Jenkinsfile',
            # Docs
            'README.md', 'README.txt', 'INSTALL', 'CHANGELOG.md',
            'LICENSE', 'COPYING',
        ]
        
        # Noms spécifiques aux bases de données
        self.database_filenames = [
            'database.db', 'data.db', 'app.db', 'main.db', 'site.db',
            'users.db', 'test.db', 'prod.db', 'dev.db',
            'database.sqlite', 'data.sqlite', 'app.sqlite',
            'database.sqlite3', 'data.sqlite3', 'app.sqlite3',
            'dump.sql', 'database.sql', 'backup.sql', 'db.sql',
            'mysql.sql', 'data.sql', 'dump.sqlite',
            'pg_dump.sql', 'postgres.sql', 'database.pgdump',
            'dump.rdb', 'redis.rdb', 'mongodb.archive',
        ]
        
        # Dossiers sensibles
        self.sensitive_directories = [
            '/admin/', '/administrator/', '/backup/', '/backups/',
            '/private/', '/secret/', '/config/', '/configs/',
            '/db/', '/database/', '/sql/', '/dumps/', '/dump/',
            '/.git/', '/.svn/', '/.hg/', '/.env/',
            '/logs/', '/log/', '/tmp/', '/temp/',
            '/api/', '/v1/', '/v2/', '/graphql',
            '/swagger/', '/api-docs/', '/phpmyadmin/',
            '/adminer/', '/shell/', '/test/', '/data/',
            '/export/', '/mysql/', '/sqlite/',
        ]
        
        # Alias de compatibilité
        self.sensitive_files = self.sensitive_extensions + self.sensitive_filenames
        
        # Extensions d'assets
        self.asset_extensions = [
            '.css', '.js', '.json', '.xml', '.txt', '.md',
            '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wav',
            '.woff', '.woff2', '.ttf', '.eot', '.otf'
        ]
        
        # Patterns d'admin
        self.admin_patterns = [
            'admin', 'administrator', 'login', 'signin', 'panel', 'dashboard',
            'backoffice', 'backend', 'cpanel', 'webmail', 'manager',
            'moderator', 'staff', 'sysadmin', 'root', 'control'
        ]
        
        # Patterns de technologies
        self.tech_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-json', 'wp-admin'],
            'Drupal': ['drupal', 'sites/all', 'drupal.js'],
            'Joomla': ['joomla', 'com_content', 'modules/mod_'],
            'Laravel': ['laravel', 'csrf-token', '_token'],
            'Django': ['django', 'csrfmiddlewaretoken', 'admin/'],
            'Rails': ['rails', 'authenticity_token', 'application.js'],
            'Express': ['express', 'x-powered-by: express'],
            'Flask': ['flask', 'x-powered-by: flask'],
            'React': ['react', 'react-dom', 'react.min.js'],
            'Vue': ['vue.js', 'vue.min.js', 'v-bind'],
            'Angular': ['angular', 'ng-app', 'ng-controller'],
            'jQuery': ['jquery', 'jquery.min.js', 'jquery-'],
            'Bootstrap': ['bootstrap', 'navbar', 'bootstrap.min.css'],
            'FontAwesome': ['font-awesome', 'fa-', 'fa-solid'],
            'GoogleAnalytics': ['ga.js', 'gtag.js', 'analytics.js'],
            'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
            'AmazonAWS': ['aws.amazon', 'x-amz', 'amazonaws']
        }
        
        # Signatures magic bytes pour identification
        self.magic_signatures = {
            b'SQLite format 3\x00': 'sqlite',
            b'PK\x03\x04': 'zip',
            b'PK\x05\x06': 'zip_empty',
            b'\x1f\x8b': 'gzip',
            b'BZh': 'bzip2',
            b'\xfd7zXZ\x00': 'xz',
            b'\x89PNG\r\n\x1a\n': 'png',
            b'\xff\xd8\xff': 'jpeg',
            b'GIF87a': 'gif',
            b'GIF89a': 'gif',
            b'%PDF-': 'pdf',
            b'\x7fELF': 'elf',
            b'MZ': 'exe',
            b'Rar!\x1a\x07': 'rar',
            b'7z\xbc\xaf\x27\x1c': '7z',
            b'REDIS': 'redis_dump',
            b'BSON': 'bson',
            b'-- MySQL dump': 'mysql_dump',
            b'-- PostgreSQL database dump': 'postgres_dump',
            b'-- SQLite': 'sqlite_dump',
        }
        
        self.clear_screen()
        self.show_banner()
    
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def colorize(self, text, color='white', bold=False):
        colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'bold': '\033[1m',
            'end': '\033[0m'
        }
        bold_text = colors['bold'] if bold else ''
        return f"{colors.get(color, '')}{bold_text}{text}{colors['end']}"
    
    def show_banner(self):
        banner = f"""
{self.colorize('╔══════════════════════════════════════════════════════════════════════════════╗', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('██╗ █████╗ ████████╗██╗  ██╗███╗   ██╗██╗███████╗██╗     ██╗   ██╗', 'red')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('██║██╔══██╗╚══██╔══╝██║  ██║████╗  ██║██║██╔════╝██║     ██║   ██║', 'red')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('██║███████║   ██║   ███████║██╔██╗ ██║██║█████╗  ██║     ██║   ██║', 'red')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('██║██╔══██║   ██║   ██╔══██║██║╚██╗██║██║██╔══╝  ██║     ██║   ██║', 'red')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('██║██║  ██║   ██║   ██║  ██║██║ ╚████║██║███████╗███████╗╚██████╔╝', 'red')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚══════╝╚══════╝ ╚═════╝ ', 'red')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('              WEB CRAWLER PRO v4.0 - JATHNIEL EDITION', 'yellow')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('     🕷️  Crawler + Extraction de bases de données exposées  🕷️', 'green')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('           🛡️  CTF / Labo - Usage autorisé uniquement  🛡️', 'magenta')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('                              ★  JATHNIEL  ★                                  ', 'yellow')}  {self.colorize('║', 'cyan')}
{self.colorize('╚══════════════════════════════════════════════════════════════════════════════╝', 'cyan')}
        """
        print(banner)
    
    def show_menu(self):
        """Affiche le menu principal."""
        status = self.colorize('● EN COURS', 'green') if self.scanning else self.colorize('○ ARRETE', 'red')
        
        menu = f"""
{self.colorize('┌────────────────────────────────────────────────────────────────────────────────────┐', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('MENU PRINCIPAL - WEB CRAWLER PRO v4.0', 'bold')}                                          {self.colorize('│', 'cyan')}
{self.colorize('├────────────────────────────────────────────────────────────────────────────────────┤', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('1.', 'yellow')}  {self.colorize('Lancer un crawl complet', 'white')}                                                 {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('2.', 'yellow')}  {self.colorize('Crawl + extraction de bases de donnees', 'white')}                              {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('3.', 'yellow')}  {self.colorize('Telecharger un fichier specifique', 'white')}                                       {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('4.', 'yellow')}  {self.colorize('Voir les resultats du crawl', 'white')}                                             {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('5.', 'yellow')}  {self.colorize('Voir les fichiers sensibles trouves', 'white')}                                     {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('6.', 'yellow')}  {self.colorize('Voir les bases de donnees extraites', 'white')}                                   {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('7.', 'yellow')}  {self.colorize('Exporter les resultats (JSON/HTML)', 'white')}                                      {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('8.', 'yellow')}  {self.colorize('Configuration', 'white')}                                                          {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('9.', 'yellow')}  {self.colorize('Statistiques du crawl', 'white')}                                                   {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('10.', 'yellow')} {self.colorize('Aide / Documentation', 'white')}                                                    {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('0.', 'yellow')}  {self.colorize('Quitter', 'white')}                                                               {self.colorize('│', 'cyan')}
{self.colorize('├────────────────────────────────────────────────────────────────────────────────────┤', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('📌 Cible:', 'bold')} {self.target_url if self.target_url else self.colorize('Aucune', 'red')}  {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('📄 Pages:', 'bold')} {self.results['statistics']['total_pages']}  {self.colorize('📁 Sensibles:', 'bold')} {self.results['statistics']['total_sensitive']}  {self.colorize('🗄️  DB:', 'bold')} {self.results['statistics']['total_databases']}  {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('📊 Statut:', 'bold')} {status}  {self.colorize('│', 'cyan')}
{self.colorize('└────────────────────────────────────────────────────────────────────────────────────┘', 'cyan')}
        """
        print(menu)
    
    def get_user_input(self, prompt, default=""):
        if default:
            prompt = f"{prompt} [{default}]: "
        else:
            prompt = f"{prompt}: "
        return input(self.colorize(prompt, 'yellow')).strip() or default
    
    def get_yes_no(self, prompt):
        while True:
            response = input(self.colorize(f"{prompt} (o/n): ", 'yellow')).lower()
            if response in ['o', 'oui', 'y', 'yes']:
                return True
            elif response in ['n', 'non', 'no']:
                return False
            else:
                print(self.colorize("❌ Repondez par 'o' ou 'n'", 'red'))

    # ==================== MOTEUR DE CRAWL ====================
    
    def crawl_complete(self, url):
        """Crawl complet avec extraction de fichiers et bases."""
        self.target_url = url
        self.target_domain = urlparse(url).netloc
        self.scanning = True
        
        # Créer les dossiers de sortie
        site_dir = f"{self.config['output_dir']}/{self.target_domain}"
        os.makedirs(site_dir, exist_ok=True)
        os.makedirs(f"{site_dir}/pages", exist_ok=True)
        os.makedirs(f"{site_dir}/assets", exist_ok=True)
        os.makedirs(f"{site_dir}/sensitive", exist_ok=True)
        os.makedirs(f"{site_dir}/databases", exist_ok=True)
        os.makedirs(f"{site_dir}/reports", exist_ok=True)
        
        print(f"\n{self.colorize('🕷️ Debut du crawl de:', 'cyan')} {url}")
        print(self.colorize("="*80, 'blue'))
        print(f"📁 Dossier de sortie: {site_dir}")
        print(f"📊 Max pages: {self.config['max_pages']}")
        print(f"📊 Max depth: {self.config['max_depth']}")
        print(f"🔍 Recherche de fichiers sensibles: {self.colorize('OUI', 'green') if self.config['download_sensitive'] else self.colorize('NON', 'red')}")
        print(f"🗄️  Analyse de bases de donnees: {self.colorize('OUI', 'green') if self.config['analyze_db'] else self.colorize('NON', 'red')}")
        print(self.colorize("="*80, 'blue'))
        
        self.results['statistics']['start_time'] = datetime.now()
        
        # Initialiser la file
        self.queue.append((url, 0))
        
        # Lancer les threads
        with ThreadPoolExecutor(max_workers=self.config['threads']) as executor:
            while self.queue and len(self.visited_urls) < self.config['max_pages']:
                if self.pause:
                    time.sleep(1)
                    continue
                
                try:
                    current_url, depth = self.queue.popleft()
                    if current_url in self.visited_urls:
                        continue
                    
                    executor.submit(self.crawl_page, current_url, depth, site_dir)
                    time.sleep(self.config['delay'])
                except IndexError:
                    break
        
        # Analyse complémentaire
        print(self.colorize("\n🔍 Analyse complémentaire...", 'yellow'))
        self.detect_technologies()
        self.find_admin_pages()
        self.extract_emails()
        
        # Statistiques finales
        self.results['statistics']['end_time'] = datetime.now()
        self.results['statistics']['duration'] = (
            self.results['statistics']['end_time'] - 
            self.results['statistics']['start_time']
        ).total_seconds()
        
        self.scanning = False
        
        print(self.colorize("\n✅ Crawl termine!", 'green'))
        print(f"📄 Pages: {self.results['statistics']['total_pages']}")
        print(f"📁 Fichiers sensibles: {self.results['statistics']['total_sensitive']}")
        print(f"🗄️  Bases de donnees: {self.results['statistics']['total_databases']}")
        print(f"📦 Assets: {self.results['statistics']['total_assets']}")
        print(f"📊 Duree: {self.results['statistics']['duration']:.2f} secondes")
    
    def crawl_page(self, url, depth, site_dir):
        """Crawl une page individuelle."""
        if url in self.visited_urls:
            return
        
        with self.lock:
            self.visited_urls.add(url)
        
        try:
            response = requests.get(
                url, 
                headers={'User-Agent': self.config['user_agent']},
                timeout=self.config['timeout'],
                verify=self.config['verify_ssl'],
                allow_redirects=self.config['follow_redirects']
            )
            
            if response.status_code != 200:
                return
            
            page_filename = self.save_page(url, response.text, site_dir)
            
            page_data = {
                'url': url,
                'depth': depth,
                'status': response.status_code,
                'size': len(response.content),
                'filename': page_filename
            }
            
            with self.lock:
                self.results['pages'].append(page_data)
                self.results['statistics']['total_pages'] += 1
                self.results['statistics']['total_size'] += len(response.content)
            
            print(f"  📄 {url} ({len(response.content)} octets)")
            
            # Extraire les liens
            if depth < self.config['max_depth']:
                links = self.extract_links(response.text, url)
                for link in links:
                    if link not in self.visited_urls:
                        with self.lock:
                            self.queue.append((link, depth + 1))
            
            # Extraire et télécharger les assets
            if self.config['download_assets']:
                self.extract_assets(response.text, url, site_dir)
            
            # Rechercher des fichiers sensibles
            if self.config['download_sensitive']:
                self.search_sensitive_in_page(response.text, url, site_dir)
            
            # Extraire les formulaires
            forms = self.extract_forms(response.text, url)
            with self.lock:
                self.results['forms'].extend(forms)
            
            # Extraire les commentaires
            comments = self.extract_comments(response.text, url)
            with self.lock:
                self.results['comments'].extend(comments)
            
        except Exception as e:
            print(f"  {self.colorize('⚠️', 'yellow')} Erreur sur {url}: {str(e)[:60]}")
    
    def extract_links(self, html, base_url):
        """Extrait les liens d'une page."""
        links = set()
        soup = BeautifulSoup(html, 'html.parser')
        
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href and not href.startswith('#') and not href.startswith('javascript:'):
                absolute_url = urljoin(base_url, href)
                if self.target_domain in urlparse(absolute_url).netloc:
                    links.add(absolute_url)
        
        for link in soup.find_all('link', href=True):
            href = link['href']
            if href:
                absolute_url = urljoin(base_url, href)
                if self.target_domain in urlparse(absolute_url).netloc:
                    links.add(absolute_url)
        
        return links
    
    def extract_assets(self, html, base_url, site_dir):
        """Extrait et télécharge les assets."""
        soup = BeautifulSoup(html, 'html.parser')
        assets_found = []
        
        for link in soup.find_all('link', rel='stylesheet', href=True):
            href = link['href']
            if href:
                absolute_url = urljoin(base_url, href)
                if any(href.endswith(ext) for ext in ['.css']):
                    assets_found.append(absolute_url)
        
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src:
                absolute_url = urljoin(base_url, src)
                if any(src.endswith(ext) for ext in ['.js']):
                    assets_found.append(absolute_url)
        
        for img in soup.find_all('img', src=True):
            src = img['src']
            if src:
                absolute_url = urljoin(base_url, src)
                if any(src.lower().endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.ico']):
                    assets_found.append(absolute_url)
        
        for asset_url in assets_found:
            self.download_asset(asset_url, site_dir)
    
    def download_asset(self, url, site_dir):
        """Télécharge un asset."""
        if url in self.visited_files:
            return
        
        with self.lock:
            self.visited_files.add(url)
        
        try:
            response = requests.get(
                url,
                headers={'User-Agent': self.config['user_agent']},
                timeout=self.config['timeout'],
                verify=self.config['verify_ssl']
            )
            
            if response.status_code == 200:
                filename = urlparse(url).path.split('/')[-1]
                if not filename:
                    filename = hashlib.md5(url.encode()).hexdigest()
                
                ext = os.path.splitext(filename)[1]
                if not ext:
                    content_type = response.headers.get('content-type', '')
                    ext = mimetypes.guess_extension(content_type) or '.bin'
                    filename += ext
                
                filepath = f"{site_dir}/assets/{filename}"
                with open(filepath, 'wb') as f:
                    f.write(response.content)
                
                with self.lock:
                    self.results['assets'].append({
                        'url': url,
                        'filename': filename,
                        'size': len(response.content)
                    })
                    self.results['statistics']['total_assets'] += 1
                
                print(f"    📦 Asset telecharge: {filename}")
                
        except Exception:
            pass
    
    def save_page(self, url, html, site_dir):
        """Sauvegarde une page."""
        filename = urlparse(url).path.replace('/', '_') or 'index'
        if not filename.endswith('.html'):
            filename += '.html'
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        
        filepath = f"{site_dir}/pages/{filename}"
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return filename
    
    # ==================== DÉTECTION FICHIERS SENSIBLES ====================
    
    def search_sensitive_in_page(self, html, url, site_dir):
        """Recherche des fichiers sensibles dans le contenu de la page."""
        found_urls = set()
        
        # === 1. Chercher dans les liens HTML ===
        urls_in_page = re.findall(r'(?:href|src|action|data-url)=["\']([^"\']+)["\']', html, re.IGNORECASE)
        
        for file_url in urls_in_page:
            file_url_lower = file_url.lower()
            
            for ext in self.sensitive_extensions:
                if file_url_lower.endswith(ext) or ext + '?' in file_url_lower or ext + '#' in file_url_lower:
                    absolute_url = urljoin(url, file_url)
                    if absolute_url not in found_urls:
                        found_urls.add(absolute_url)
                        self.download_sensitive_file(absolute_url, site_dir)
                    break
            
            for fname in self.sensitive_filenames:
                if fname.lower() in file_url_lower:
                    absolute_url = urljoin(url, file_url)
                    if absolute_url not in found_urls:
                        found_urls.add(absolute_url)
                        self.download_sensitive_file(absolute_url, site_dir)
                    break
            
            for directory in self.sensitive_directories:
                if directory.lower() in file_url_lower:
                    absolute_url = urljoin(url, file_url)
                    if absolute_url not in found_urls:
                        found_urls.add(absolute_url)
                        self.download_sensitive_file(absolute_url, site_dir)
                    break
        
        # === 2. Chercher les chemins absolus dans le texte brut ===
        ext_pattern = '|'.join([re.escape(e.lstrip('.')) for e in self.sensitive_extensions])
        paths_ext = re.findall(
            r'(/[a-zA-Z0-9_\-./]+\.(?:' + ext_pattern + r'))',
            html, re.IGNORECASE
        )
        for path in paths_ext:
            absolute_url = urljoin(url, path)
            if absolute_url not in found_urls:
                found_urls.add(absolute_url)
                self.download_sensitive_file(absolute_url, site_dir)
        
        # === 3. Chercher les liens directs vers DB ===
        db_link_patterns = [
            r'href=["\']([^"\']*\.(?:sqlite|sqlite3|db|sql|dump|bson|rdb))["\']',
            r'src=["\']([^"\']*\.(?:sqlite|sqlite3|db|sql))["\']',
            r'["\']([^"\']*/(?:db|database|backup|dump|sql)/[^"\']*)["\']',
        ]
        for pattern in db_link_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                absolute_url = urljoin(url, match)
                if absolute_url not in found_urls:
                    found_urls.add(absolute_url)
                    self.download_sensitive_file(absolute_url, site_dir)
    
    def download_sensitive_file(self, url, site_dir):
        """Télécharge un fichier sensible."""
        if url in self.visited_files:
            return False
        
        with self.lock:
            self.visited_files.add(url)
        
        try:
            response = requests.get(
                url,
                headers={'User-Agent': self.config['user_agent']},
                timeout=self.config['timeout'],
                verify=self.config['verify_ssl']
            )
            
            if response.status_code != 200:
                return False
            
            content_type = response.headers.get('content-type', '').lower()
            content_len = len(response.content)
            content = response.content
            
            # Détecter contenu intéressant
            is_interesting_content = (
                b'password' in content.lower() or
                b'api_key' in content.lower() or
                b'secret' in content.lower() or
                b'token' in content.lower() or
                b'BEGIN RSA' in content or
                b'BEGIN PRIVATE KEY' in content or
                b'BEGIN OPENSSH' in content or
                b'<config' in content.lower() or
                b'<?xml' in content.lower() or
                b'SQLite format' in content or
                b'CREATE TABLE' in content[:5000]
            )
            
            # Ne pas télécharger les gros HTML
            if 'text/html' in content_type and content_len > 100000 and not is_interesting_content:
                return False
            
            # Limiter à 50 Mo pour les DB
            max_size = 50 * 1024 * 1024 if any(url.endswith(ext) for ext in ['.sql', '.db', '.sqlite', '.sqlite3', '.dump']) else 10 * 1024 * 1024
            if content_len > max_size:
                return False
            
            filename = urlparse(url).path.split('/')[-1]
            if not filename or filename.endswith('/'):
                filename = 'index_' + hashlib.md5(url.encode()).hexdigest()[:8]
            
            if '.' not in filename:
                ext = mimetypes.guess_extension(content_type.split(';')[0].strip()) or '.bin'
                filename += ext
            
            filename = re.sub(r'[<>:"/\\|?*]', '_', filename)[:100]
            
            # Identifier le vrai type
            real_type = self.identify_file_type(content)
            
            # Choisir le dossier de destination
            if real_type in ['sqlite', 'mysql_dump', 'postgres_dump', 'redis_dump', 'bson'] or \
               any(filename.lower().endswith(ext) for ext in ['.sql', '.db', '.sqlite', '.sqlite3', '.dump', '.bson', '.rdb']):
                dest_dir = f"{site_dir}/databases"
                is_database = True
            else:
                dest_dir = f"{site_dir}/sensitive"
                is_database = False
            
            filepath = f"{dest_dir}/{filename}"
            if os.path.exists(filepath):
                base, ext = os.path.splitext(filename)
                filename = f"{base}_{hashlib.md5(url.encode()).hexdigest()[:6]}{ext}"
                filepath = f"{dest_dir}/{filename}"
            
            with open(filepath, 'wb') as f:
                f.write(content)
            
            file_info = {
                'url': url,
                'filename': filename,
                'size': content_len,
                'path': filepath,
                'type': self.classify_sensitive_file(filename),
                'real_type': real_type,
                'content_preview': content[:200].decode('utf-8', errors='ignore')
            }
            
            with self.lock:
                if is_database:
                    self.results['databases'].append(file_info)
                    self.results['statistics']['total_databases'] += 1
                    print(f"    {self.colorize('🗄️  BASE DE DONNEES:', 'magenta')} {filename}")
                else:
                    self.results['sensitive_files'].append(file_info)
                    self.results['statistics']['total_sensitive'] += 1
                    print(f"    {self.colorize('🔴 FICHIER SENSIBLE:', 'red')} {filename}")
                print(f"        📍 {url}")
                print(f"        📦 {content_len} octets | Type: {real_type}")
            
            # Analyse auto si c'est une DB et que l'option est activée
            if is_database and self.config['analyze_db']:
                self.analyze_database(filepath, real_type, filename)
            
            return True
        
        except Exception as e:
            print(f"    {self.colorize('⚠️', 'yellow')} Erreur sur {url}: {str(e)[:60]}")
            return False
    
    def identify_file_type(self, content: bytes) -> str:
        """Identifie le vrai type de fichier par magic bytes."""
        for magic, name in self.magic_signatures.items():
            if content.startswith(magic):
                return name
        
        # Vérification supplémentaire pour les dumps SQL
        preview = content[:5000]
        if b'CREATE TABLE' in preview or b'INSERT INTO' in preview:
            if b'`' in preview or b'ENGINE=' in preview:
                return 'mysql_dump'
            return 'sql_dump'
        
        return 'unknown'
    
    def classify_sensitive_file(self, filename):
        """Classifie le type de fichier sensible."""
        filename_lower = filename.lower()
        
        if any(x in filename_lower for x in ['.sqlite', '.sqlite3', '.db3', '.s3db']):
            return 'SQLite Database'
        elif '.sql' in filename_lower or 'dump' in filename_lower:
            return 'SQL Dump'
        elif '.rdb' in filename_lower:
            return 'Redis Dump'
        elif '.bson' in filename_lower or 'mongo' in filename_lower:
            return 'MongoDB Export'
        elif '.pgdump' in filename_lower:
            return 'PostgreSQL Dump'
        elif 'config' in filename_lower or '.env' in filename_lower or '.ini' in filename_lower:
            return 'Configuration'
        elif 'backup' in filename_lower or '.bak' in filename_lower:
            return 'Backup'
        elif '.log' in filename_lower:
            return 'Log'
        elif '.key' in filename_lower or '.pem' in filename_lower or 'id_rsa' in filename_lower or '.crt' in filename_lower:
            return 'Certificate/Key'
        elif '.git' in filename_lower or '.svn' in filename_lower:
            return 'Version Control'
        elif 'wp-config' in filename_lower:
            return 'WordPress Config'
        elif 'robots.txt' in filename_lower or 'sitemap' in filename_lower:
            return 'SEO/Discovery'
        elif any(x in filename_lower for x in ['.zip', '.rar', '.7z', '.tar', '.gz']):
            return 'Archive'
        elif 'package.json' in filename_lower or 'composer.json' in filename_lower or 'requirements.txt' in filename_lower:
            return 'Dependencies'
        elif '.bin' in filename_lower or '.dat' in filename_lower:
            return 'Binary'
        else:
            return 'Other'
    
    # ==================== ANALYSE BASES DE DONNÉES ====================
    
    def analyze_database(self, filepath: str, real_type: str, filename: str):
        """Analyse une base de données trouvée."""
        print(f"    {self.colorize('🔬 Analyse de la base...', 'cyan')}")
        
        analysis = {
            'file': filename,
            'type': real_type,
            'tables': {},
            'error': None
        }
        
        try:
            if real_type == 'sqlite':
                analysis = self.analyze_sqlite(filepath, filename)
            elif real_type in ['mysql_dump', 'postgres_dump', 'sql_dump']:
                analysis = self.analyze_sql_dump(filepath, filename)
            elif real_type == 'gzip':
                # DB compressée
                analysis = self.analyze_compressed_db(filepath, filename)
            elif real_type == 'zip':
                # Archive peut contenir une DB
                analysis = self.analyze_zip_archive(filepath, filename)
            elif real_type == 'redis_dump':
                analysis = self.analyze_redis_dump(filepath, filename)
            elif real_type == 'bson':
                analysis = self.analyze_bson(filepath, filename)
            else:
                # Tentative générique
                analysis = self.analyze_generic_db(filepath, filename)
        
        except Exception as e:
            analysis['error'] = str(e)
        
        # Stocker dans les résultats
        with self.lock:
            self.results['db_contents'][filename] = analysis
        
        # Afficher le résumé
        self.display_db_summary(analysis)
    
    def analyze_sqlite(self, filepath: str, filename: str) -> dict:
        """Analyse une base SQLite."""
        result = {
            'file': filename,
            'type': 'SQLite',
            'tables': {},
            'error': None
        }
        
        try:
            # Copier dans /tmp pour éviter les lock
            tmp_path = f"/tmp/{filename}_analyze"
            shutil.copy2(filepath, tmp_path)
            
            conn = sqlite3.connect(tmp_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM `{table}`")
                    count = cursor.fetchone()[0]
                    
                    cursor.execute(f"SELECT * FROM `{table}` LIMIT 10")
                    rows = cursor.fetchall()
                    cols = [desc[0] for desc in cursor.description] if cursor.description else []
                    
                    result['tables'][table] = {
                        'columns': cols,
                        'row_count': count,
                        'sample': [list(row) for row in rows]
                    }
                except Exception as e:
                    result['tables'][table] = {'error': str(e)}
            
            conn.close()
            os.remove(tmp_path)
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def analyze_sql_dump(self, filepath: str, filename: str) -> dict:
        """Analyse un dump SQL (MySQL, PostgreSQL, générique)."""
        result = {
            'file': filename,
            'type': 'SQL Dump',
            'tables': {},
            'error': None
        }
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Détecter le SGBD
            if '-- MySQL dump' in content[:200]:
                result['type'] = 'MySQL Dump'
            elif '-- PostgreSQL database dump' in content[:200]:
                result['type'] = 'PostgreSQL Dump'
            
            # Trouver les tables
            create_re = re.compile(r'CREATE TABLE\s+(?:IF NOT EXISTS\s+)?[`"\[]?(\w+)[`"\]]?', re.IGNORECASE)
            tables = create_re.findall(content)
            
            for table in tables:
                insert_re = re.compile(
                    rf'INSERT INTO\s+[`"\[]?{re.escape(table)}[`"\]]?\s+.*?;',
                    re.IGNORECASE | re.DOTALL
                )
                inserts = insert_re.findall(content)
                
                # Extraire les colonnes du CREATE TABLE
                create_table_re = re.compile(
                    rf'CREATE TABLE\s+[`"\[]?{re.escape(table)}[`"\]]?\s*\((.*?)\)',
                    re.IGNORECASE | re.DOTALL
                )
                create_match = create_table_re.search(content)
                columns = []
                if create_match:
                    col_lines = create_match.group(1).split(',')
                    for line in col_lines:
                        col_match = re.match(r'\s*[`"\[]?(\w+)[`"\]]?', line)
                        if col_match:
                            col_name = col_match.group(1)
                            if col_name.upper() not in ['PRIMARY', 'KEY', 'UNIQUE', 'INDEX', 'CONSTRAINT', 'FOREIGN']:
                                columns.append(col_name)
                
                result['tables'][table] = {
                    'columns': columns,
                    'insert_count': len(inserts),
                    'sample': [ins[:300] for ins in inserts[:3]]
                }
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def analyze_compressed_db(self, filepath: str, filename: str) -> dict:
        """Analyse une DB compressée (gzip)."""
        result = {
            'file': filename,
            'type': 'Compressed DB',
            'tables': {},
            'error': None
        }
        
        try:
            with gzip.open(filepath, 'rb') as f:
                decompressed = f.read()
            
            # Sauvegarder la version décompressée
            decompressed_path = filepath.replace('.gz', '')
            with open(decompressed_path, 'wb') as f:
                f.write(decompressed)
            
            # Identifier le type
            real_type = self.identify_file_type(decompressed)
            result['decompressed_type'] = real_type
            
            # Analyser selon le type
            if real_type == 'sqlite':
                return self.analyze_sqlite(decompressed_path, filename.replace('.gz', ''))
            elif 'dump' in real_type:
                return self.analyze_sql_dump(decompressed_path, filename.replace('.gz', ''))
            else:
                result['preview'] = decompressed[:500].decode('utf-8', errors='ignore')
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def analyze_zip_archive(self, filepath: str, filename: str) -> dict:
        """Analyse une archive ZIP (peut contenir une DB)."""
        result = {
            'file': filename,
            'type': 'ZIP Archive',
            'contents': [],
            'db_found': [],
            'error': None
        }
        
        try:
            with zipfile.ZipFile(filepath, 'r') as z:
                for name in z.namelist():
                    result['contents'].append(name)
                    
                    # Si c'est une DB dans l'archive
                    if any(name.lower().endswith(ext) for ext in ['.sql', '.db', '.sqlite', '.sqlite3', '.dump']):
                        extract_dir = f"{os.path.dirname(filepath)}/extracted_{hashlib.md5(filename.encode()).hexdigest()[:6]}"
                        os.makedirs(extract_dir, exist_ok=True)
                        z.extract(name, extract_dir)
                        extracted_path = os.path.join(extract_dir, name)
                        
                        real_type = 'unknown'
                        with open(extracted_path, 'rb') as f:
                            real_type = self.identify_file_type(f.read(100))
                        
                        result['db_found'].append({
                            'name': name,
                            'extracted_path': extracted_path,
                            'type': real_type
                        })
                        
                        # Analyser la DB extraite
                        if real_type == 'sqlite':
                            sub_analysis = self.analyze_sqlite(extracted_path, name)
                            result['tables'] = sub_analysis.get('tables', {})
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def analyze_redis_dump(self, filepath: str, filename: str) -> dict:
        """Analyse un dump Redis (RDB) - basique."""
        result = {
            'file': filename,
            'type': 'Redis RDB',
            'keys': [],
            'error': None
        }
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # Extraction basique des strings (les clés Redis sont souvent en clair)
            strings_found = re.findall(rb'[a-zA-Z0-9_:\-]{3,50}', content)
            unique_keys = list(set([s.decode('utf-8', errors='ignore') for s in strings_found]))
            
            # Filtrer les clés probables (pas les magic bytes)
            result['keys'] = [k for k in unique_keys if not k.startswith('REDIS')][:100]
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def analyze_bson(self, filepath: str, filename: str) -> dict:
        """Analyse un fichier BSON (MongoDB)."""
        result = {
            'file': filename,
            'type': 'MongoDB BSON',
            'preview': '',
            'error': None
        }
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read(10000)
            
            # Essayer de décoder en tant que texte
            result['preview'] = content[:500].decode('utf-8', errors='ignore')
            
            # Chercher des patterns de documents MongoDB
            strings_found = re.findall(rb'[a-zA-Z0-9_]{3,50}', content)
            unique = list(set([s.decode('utf-8', errors='ignore') for s in strings_found]))
            result['fields'] = unique[:50]
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def analyze_generic_db(self, filepath: str, filename: str) -> dict:
        """Analyse générique - cherche du SQL ou des données structurées."""
        result = {
            'file': filename,
            'type': 'Unknown (tentative generique)',
            'tables': {},
            'error': None
        }
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # Chercher des CREATE TABLE / INSERT
            text = content.decode('utf-8', errors='ignore')
            
            create_re = re.compile(r'CREATE TABLE\s+(?:IF NOT EXISTS\s+)?[`"\[]?(\w+)[`"\]]?', re.IGNORECASE)
            tables = create_re.findall(text)
            
            for table in tables:
                insert_re = re.compile(
                    rf'INSERT INTO\s+[`"\[]?{re.escape(table)}[`"\]]?\s+.*?;',
                    re.IGNORECASE | re.DOTALL
                )
                inserts = insert_re.findall(text)
                result['tables'][table] = {
                    'insert_count': len(inserts),
                    'sample': [ins[:200] for ins in inserts[:2]]
                }
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def display_db_summary(self, analysis: dict):
        """Affiche un résumé de l'analyse de la DB."""
        print(f"    {self.colorize('┌─ Résumé de la base', 'cyan')}")
        print(f"    {self.colorize('│', 'cyan')} Fichier: {analysis.get('file', 'N/A')}")
        print(f"    {self.colorize('│', 'cyan')} Type: {analysis.get('type', 'N/A')}")
        
        tables = analysis.get('tables', {})
        if tables:
            print(f"    {self.colorize('│', 'cyan')} Tables: {len(tables)}")
            for table_name, table_data in list(tables.items())[:10]:
                if 'error' in table_data:
                    print(f"    {self.colorize('│', 'cyan')}   - {table_name}: [ERREUR]")
                else:
                    cols = table_data.get('columns', [])
                    count = table_data.get('row_count', 0) or table_data.get('insert_count', 0)
                    print(f"    {self.colorize('│', 'cyan')}   - {table_name}: {count} lignes, {len(cols)} colonnes")
        
        if analysis.get('keys'):
            print(f"    {self.colorize('│', 'cyan')} Cles Redis: {len(analysis['keys'])}")
        
        if analysis.get('error'):
            print(f"    {self.colorize('│', 'yellow')} Erreur: {analysis['error'][:80]}")
        
        print(f"    {self.colorize('└─', 'cyan')}")
    
    # ==================== ANALYSE AVANCÉE ====================
    
    def detect_technologies(self):
        """Détecte les technologies utilisées."""
        techs_found = set()
        
        for page in self.results['pages']:
            try:
                response = requests.get(
                    page['url'],
                    headers={'User-Agent': self.config['user_agent']},
                    timeout=5,
                    verify=self.config['verify_ssl']
                )
                
                headers = response.headers
                text = response.text
                
                for tech, patterns in self.tech_patterns.items():
                    for pattern in patterns:
                        if pattern.lower() in text.lower():
                            techs_found.add(tech)
                        if pattern.lower() in str(headers).lower():
                            techs_found.add(tech)
                
                server = headers.get('Server', '')
                if 'nginx' in server.lower():
                    techs_found.add('Nginx')
                elif 'apache' in server.lower():
                    techs_found.add('Apache')
                elif 'cloudflare' in server.lower():
                    techs_found.add('Cloudflare')
                
            except Exception:
                pass
        
        self.results['technologies'] = list(techs_found)
    
    def find_admin_pages(self):
        """Recherche des pages d'administration."""
        base_url = self.target_url.rstrip('/')
        admin_urls = []
        
        for pattern in self.admin_patterns:
            for ext in ['', '.php', '.html', '.asp', '.aspx']:
                url = f"{base_url}/{pattern}{ext}"
                try:
                    response = requests.get(
                        url,
                        headers={'User-Agent': self.config['user_agent']},
                        timeout=5,
                        verify=self.config['verify_ssl']
                    )
                    
                    if response.status_code == 200:
                        admin_urls.append(url)
                        print(f"    🔐 Page admin trouvee: {url}")
                        
                        if self.config['download_sensitive']:
                            self.download_sensitive_file(url, f"{self.config['output_dir']}/{self.target_domain}")
                        
                except Exception:
                    pass
        
        self.results['admin_pages'] = admin_urls
    
    def extract_emails(self):
        """Extrait les adresses email."""
        emails = set()
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        
        for page in self.results['pages']:
            try:
                response = requests.get(
                    page['url'],
                    headers={'User-Agent': self.config['user_agent']},
                    timeout=5,
                    verify=self.config['verify_ssl']
                )
                found = email_pattern.findall(response.text)
                emails.update(found)
            except Exception:
                pass
        
        self.results['emails'] = list(emails)
        if emails:
            print(f"\n    📧 Emails trouves: {len(emails)}")
            for email in list(emails)[:10]:
                print(f"        - {email}")
    
    def extract_forms(self, html, base_url):
        """Extrait les formulaires."""
        forms = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            absolute_action = urljoin(base_url, action)
            
            fields = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                field = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'required': input_tag.has_attr('required')
                }
                fields.append(field)
            
            has_csrf = any('csrf' in str(field).lower() or 'token' in str(field).lower() for field in fields)
            
            forms.append({
                'url': base_url,
                'action': absolute_action,
                'method': method,
                'fields': fields,
                'has_csrf': has_csrf
            })
        
        return forms
    
    def extract_comments(self, html, url):
        """Extrait les commentaires HTML."""
        comments = []
        comment_pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
        
        found = comment_pattern.findall(html)
        for comment in found:
            comment = comment.strip()
            if len(comment) > 10 and '<!--' not in comment:
                comments.append({
                    'page': url,
                    'comment': comment[:200]
                })
        
        return comments
    
    # ==================== AFFICHAGE ET EXPORT ====================
    
    def download_specific_file(self):
        """Télécharge un fichier spécifique."""
        print(self.colorize("\n📥 TELECHARGER UN FICHIER SPECIFIQUE", 'bold'))
        print(self.colorize("="*60, 'cyan'))
        
        url = self.get_user_input("URL du fichier", "")
        if not url:
            return
        
        if not self.target_domain:
            self.target_domain = urlparse(url).netloc
        
        site_dir = f"{self.config['output_dir']}/{self.target_domain}"
        os.makedirs(site_dir, exist_ok=True)
        os.makedirs(f"{site_dir}/sensitive", exist_ok=True)
        os.makedirs(f"{site_dir}/databases", exist_ok=True)
        
        print(f"\n🔍 Tentative de telechargement: {url}")
        success = self.download_sensitive_file(url, site_dir)
        
        if success:
            print(self.colorize("\n✅ Fichier telecharge avec succes!", 'green'))
        else:
            print(self.colorize("\n❌ Echec du telechargement", 'red'))
        
        input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))
    
    def show_sensitive_files(self):
        """Affiche les fichiers sensibles trouvés."""
        if not self.results['sensitive_files']:
            print(self.colorize("\n❌ Aucun fichier sensible trouve", 'yellow'))
            return
        
        print(self.colorize("\n🔴 FICHIERS SENSIBLES TROUVES", 'bold'))
        print(self.colorize("="*60, 'cyan'))
        
        by_type = defaultdict(list)
        for file in self.results['sensitive_files']:
            by_type[file['type']].append(file)
        
        for ftype, files in by_type.items():
            print(f"\n{self.colorize(f'📁 {ftype} ({len(files)})', 'yellow', bold=True)}")
            for file in files:
                print(f"  • {self.colorize(file['filename'], 'red')} ({file['size']} octets) [{file.get('real_type', 'unknown')}]")
                print(f"    📍 {file['url']}")
    
    def show_databases(self):
        """Affiche les bases de données trouvées."""
        if not self.results['databases']:
            print(self.colorize("\n❌ Aucune base de donnees trouvee", 'yellow'))
            return
        
        print(self.colorize("\n🗄️  BASES DE DONNEES TROUVEES", 'bold'))
        print(self.colorize("="*60, 'cyan'))
        
        for i, db in enumerate(self.results['databases'], 1):
            print(f"\n{i}. {self.colorize(db['filename'], 'magenta')} ({db['size']} octets)")
            print(f"   📍 {db['url']}")
            print(f"   📂 {db['path']}")
            print(f"   🔎 Type reel: {db.get('real_type', 'unknown')}")
            
            # Afficher le contenu analysé
            analysis = self.results['db_contents'].get(db['filename'], {})
            tables = analysis.get('tables', {})
            
            if tables:
                print(f"   📊 {len(tables)} table(s):")
                for table_name, table_data in tables.items():
                    if 'error' in table_data:
                        print(f"      - {table_name}: [ERREUR]")
                    else:
                        cols = table_data.get('columns', [])
                        count = table_data.get('row_count', 0) or table_data.get('insert_count', 0)
                        print(f"      - {table_name}: {count} lignes")
                        if cols:
                            print(f"        Colonnes: {', '.join(cols[:10])}")
                        
                        # Afficher un échantillon
                        sample = table_data.get('sample', [])
                        if sample:
                            print(f"        Echantillon:")
                            for row in sample[:3]:
                                if isinstance(row, list):
                                    print(f"          {' | '.join(str(c)[:30] for c in row)}")
                                else:
                                    print(f"          {str(row)[:100]}")
            
            if analysis.get('keys'):
                print(f"   🔑 {len(analysis['keys'])} cles Redis detectees")
                for key in analysis['keys'][:10]:
                    print(f"      - {key}")
            
            if analysis.get('error'):
                print(f"   ⚠️  Erreur: {analysis['error'][:100]}")
    
    def show_results(self):
        """Affiche les résultats complets."""
        print(self.colorize("\n📊 RESULTATS DU CRAWL", 'bold'))
        print(self.colorize("="*60, 'cyan'))
        
        print(f"\n📄 Pages decouvertes: {len(self.results['pages'])}")
        print(f"📦 Assets telecharges: {len(self.results['assets'])}")
        print(f"🔴 Fichiers sensibles: {len(self.results['sensitive_files'])}")
        print(f"🗄️  Bases de donnees: {len(self.results['databases'])}")
        print(f"📝 Formulaires: {len(self.results['forms'])}")
        print(f"📧 Emails: {len(self.results['emails'])}")
        print(f"🔐 Pages admin: {len(self.results['admin_pages'])}")
        
        if self.results['technologies']:
            print(f"\n⚙️ Technologies detectees:")
            for tech in self.results['technologies']:
                print(f"  - {tech}")
    
    def export_results(self):
        """Exporte les résultats."""
        print(self.colorize("\n📤 EXPORT DES RESULTATS", 'bold'))
        print(self.colorize("="*60, 'cyan'))
        
        print("Formats disponibles:")
        print("  1. JSON")
        print("  2. HTML")
        print("  3. CSV")
        
        choice = self.get_user_input("Choisissez le format", "1")
        
        site_dir = f"{self.config['output_dir']}/{self.target_domain}"
        os.makedirs(f"{site_dir}/reports", exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if choice == '1':
            filename = f"{site_dir}/reports/crawl_report_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            print(self.colorize(f"✅ Exporte dans: {filename}", 'green'))
        
        elif choice == '2':
            filename = f"{site_dir}/reports/crawl_report_{timestamp}.html"
            self.export_html_report(filename)
            print(self.colorize(f"✅ Exporte dans: {filename}", 'green'))
        
        elif choice == '3':
            filename = f"{site_dir}/reports/crawl_report_{timestamp}.csv"
            self.export_csv_report(filename)
            print(self.colorize(f"✅ Exporte dans: {filename}", 'green'))
        
        input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))
    
    def export_html_report(self, filename):
        """Exporte un rapport HTML."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Crawl Report - JATHNIEL v4.0</title>
    <style>
        body {{ font-family: Arial; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 10px; }}
        h1 {{ color: #d32f2f; }}
        .header {{ background: #1e1e1e; color: white; padding: 15px; border-radius: 5px; }}
        .stats {{ display: flex; gap: 20px; flex-wrap: wrap; }}
        .stat-box {{ background: #e3f2fd; padding: 15px; border-radius: 5px; flex: 1; min-width: 150px; }}
        .stat-box.db {{ background: #f3e5f5; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #1976d2; }}
        .stat-box.db .stat-value {{ color: #7b1fa2; }}
        .stat-label {{ font-size: 14px; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th {{ background: #1e1e1e; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        .sensitive {{ background: #ffebee; border-left: 4px solid #d32f2f; }}
        .database {{ background: #f3e5f5; border-left: 4px solid #7b1fa2; }}
        .admin {{ background: #fff3e0; border-left: 4px solid #f57c00; }}
        .db-detail {{ background: #fafafa; padding: 15px; margin: 10px 0; border-left: 4px solid #7b1fa2; }}
        .db-detail pre {{ background: #263238; color: #aed581; padding: 10px; overflow-x: auto; border-radius: 4px; }}
        .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕷️ Web Crawl Report v4.0</h1>
            <p>Generated by JATHNIEL-WEB-CRAWLER-PRO</p>
            <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Target: {self.target_url}</p>
        </div>
        
        <h2>📊 Statistics</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">{self.results['statistics']['total_pages']}</div>
                <div class="stat-label">Pages</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{self.results['statistics']['total_assets']}</div>
                <div class="stat-label">Assets</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{self.results['statistics']['total_sensitive']}</div>
                <div class="stat-label">Sensitive Files</div>
            </div>
            <div class="stat-box db">
                <div class="stat-value">{self.results['statistics']['total_databases']}</div>
                <div class="stat-label">🗄️ Databases</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{len(self.results['emails'])}</div>
                <div class="stat-label">Emails</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{self.results['statistics']['duration']:.2f}s</div>
                <div class="stat-label">Duration</div>
            </div>
        </div>
        
        <h2>🗄️ Databases Found ({len(self.results['databases'])})</h2>"""
        
        for db in self.results['databases']:
            analysis = self.results['db_contents'].get(db['filename'], {})
            html += f"""
            <div class="db-detail">
                <h3>{db['filename']} <span style="color: #7b1fa2;">({db.get('real_type', 'unknown')})</span></h3>
                <p><strong>URL:</strong> <a href="{db['url']}" target="_blank">{db['url']}</a></p>
                <p><strong>Size:</strong> {db['size']} bytes</p>
                <p><strong>Path:</strong> {db['path']}</p>
            """
            
            tables = analysis.get('tables', {})
            if tables:
                html += f"<p><strong>Tables ({len(tables)}):</strong></p>"
                for table_name, table_data in tables.items():
                    if 'error' in table_data:
                        html += f"<p>⚠️ {table_name}: {table_data['error']}</p>"
                    else:
                        cols = table_data.get('columns', [])
                        count = table_data.get('row_count', 0) or table_data.get('insert_count', 0)
                        html += f"""
                        <details>
                            <summary><strong>{table_name}</strong> ({count} rows, {len(cols)} columns)</summary>
                            <p>Columns: {', '.join(cols)}</p>
                            <pre>{json.dumps(table_data.get('sample', [])[:5], indent=2, default=str)[:2000]}</pre>
                        </details>
                        """
            
            if analysis.get('keys'):
                html += f"<p><strong>Redis Keys ({len(analysis['keys'])}):</strong></p><pre>{chr(10).join(analysis['keys'][:20])}</pre>"
            
            html += "</div>"
        
        html += """
        <h2>🔴 Sensitive Files</h2>
        <table>
            <tr>
                <th>#</th>
                <th>File</th>
                <th>Type</th>
                <th>Real Type</th>
                <th>Size</th>
                <th>URL</th>
            </tr>"""
        
        for i, file in enumerate(self.results['sensitive_files'], 1):
            html += f"""
            <tr class="sensitive">
                <td>{i}</td>
                <td>{file['filename']}</td>
                <td>{file['type']}</td>
                <td>{file.get('real_type', 'unknown')}</td>
                <td>{file['size']} bytes</td>
                <td><a href="{file['url']}" target="_blank">{file['url'][:60]}...</a></td>
            </tr>"""
        
        html += """
        </table>
        
        <h2>🔐 Admin Pages</h2>
        <table>
            <tr><th>#</th><th>URL</th></tr>"""
        
        for i, url in enumerate(self.results['admin_pages'], 1):
            html += f'<tr class="admin"><td>{i}</td><td><a href="{url}" target="_blank">{url}</a></td></tr>'
        
        html += """
        </table>
        
        <h2>📧 Emails</h2>
        <ul>"""
        
        for email in self.results['emails'][:30]:
            html += f"<li>{email}</li>"
        
        html += """
        </ul>
        
        <div class="footer">
            <p>Generated by JATHNIEL-WEB-CRAWLER-PRO v4.0</p>
            <p>CTF / Lab Tool - For educational and authorized purposes only</p>
            <p>★ JATHNIEL ★</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def export_csv_report(self, filename):
        """Exporte un rapport CSV."""
        import csv
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            writer.writerow(['DATABASES'])
            writer.writerow(['File', 'Type', 'Size', 'URL', 'Tables'])
            for db in self.results['databases']:
                analysis = self.results['db_contents'].get(db['filename'], {})
                tables = list(analysis.get('tables', {}).keys())
                writer.writerow([db['filename'], db.get('real_type', ''), db['size'], db['url'], ', '.join(tables)])
            
            writer.writerow([])
            
            writer.writerow(['SENSITIVE FILES'])
            writer.writerow(['File', 'Type', 'Real Type', 'Size', 'URL'])
            for file in self.results['sensitive_files']:
                writer.writerow([file['filename'], file['type'], file.get('real_type', ''), file['size'], file['url']])
            
            writer.writerow([])
            
            writer.writerow(['ADMIN PAGES'])
            writer.writerow(['URL'])
            for url in self.results['admin_pages']:
                writer.writerow([url])
            
            writer.writerow([])
            
            writer.writerow(['EMAILS'])
            writer.writerow(['Email'])
            for email in self.results['emails']:
                writer.writerow([email])
    
    def show_statistics(self):
        """Affiche les statistiques."""
        stats = self.results['statistics']
        
        print(self.colorize("\n📊 STATISTIQUES DU CRAWL", 'bold'))
        print(self.colorize("="*60, 'cyan'))
        
        print(f"\n📄 Pages decouvertes: {stats['total_pages']}")
        print(f"📦 Assets telecharges: {stats['total_assets']}")
        print(f"🔴 Fichiers sensibles: {stats['total_sensitive']}")
        print(f"🗄️  Bases de donnees: {stats['total_databases']}")
        print(f"📦 Taille totale: {self.format_size(stats['total_size'])}")
        print(f"⏱️  Duree: {stats['duration']:.2f} secondes")
        if stats['duration'] > 0:
            print(f"🚀 Vitesse moyenne: {stats['total_pages'] / stats['duration']:.2f} pages/sec")
    
    def format_size(self, bytes):
        """Formate la taille en unités lisibles."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} TB"
    
    # ==================== CONFIGURATION ====================
    
    def show_config(self):
        """Affiche la configuration."""
        print(self.colorize("\n⚙️ CONFIGURATION", 'bold'))
        print(self.colorize("="*60, 'cyan'))
        
        for key, value in self.config.items():
            print(f"  {key}: {self.colorize(str(value), 'green' if value else 'yellow')}")
        
        input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))
    
    def show_help(self):
        """Affiche l'aide."""
        help_text = f"""
{self.colorize('📚 WEB CRAWLER PRO v4.0 - GUIDE D UTILISATION', 'bold')}
{self.colorize('='*60, 'cyan')}

{self.colorize('1. Crawl complet', 'green')}
   - Explore tout le site
   - Telecharge les pages, assets et fichiers sensibles
   - Analyse les technologies et emails

{self.colorize('2. Extraction de bases de donnees', 'green')}
   - Recherche automatique des DB exposees
   - Identification par magic bytes (extension trompeuse)
   - Analyse automatique du contenu
   - Extraction des tables, colonnes et donnees

{self.colorize('3. Telechargement specifique', 'green')}
   - Telecharge un fichier specifique
   - Utile pour tester des URLs candidates

{self.colorize('4. Export des resultats', 'green')}
   - JSON: Donnees structurees
   - HTML: Rapport visuel avec details DB
   - CSV: Analyse dans Excel

{self.colorize('🆕 NOUVEAU v4.0 :', 'yellow')}
   - Detection SQLite / MySQL / PostgreSQL / MongoDB / Redis
   - Magic bytes (admin.bin peut etre une SQLite)
   - Analyse auto : tables, colonnes, echantillons
   - Extraction des archives ZIP contenant des DB
   - Support des DB compressees (.gz)

{self.colorize('⚠️ RAPPEL', 'red')}
   - Cadre CTF / Labo uniquement
   - Vos propres machines ou autorisation ecrite
   - Usage educatif et de securite
        """
        print(help_text)
    
    # ==================== MENU PRINCIPAL ====================
    
    def run(self):
        """Boucle principale."""
        while True:
            self.clear_screen()
            self.show_banner()
            self.show_menu()
            
            choice = input(self.colorize("\n👉 Votre choix: ", 'bold')).strip()
            
            if choice == '1':
                url = self.get_user_input("URL cible", "https://example.com")
                if url:
                    self.crawl_complete(url)
                input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))
            
            elif choice == '2':
                url = self.get_user_input("URL cible", "https://example.com")
                if url:
                    self.config['download_sensitive'] = True
                    self.config['analyze_db'] = True
                    self.crawl_complete(url)
                input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))
            
            elif choice == '3':
                self.download_specific_file()
            
            elif choice == '4':
                self.show_results()
                input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))
            
            elif choice == '5':
                self.show_sensitive_files()
                input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))
            
            elif choice == '6':
                self.show_databases()
                input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))
            
            elif choice == '7':
                self.export_results()
            
            elif choice == '8':
                self.show_config()
            
            elif choice == '9':
                self.show_statistics()
                input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))
            
            elif choice == '10':
                self.show_help()
                input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))
            
            elif choice == '0':
                print(self.colorize("\n👋 Au revoir!", 'green'))
                sys.exit(0)
            
            else:
                print(self.colorize("❌ Choix invalide", 'red'))
                time.sleep(1)


# ==================== MAIN ====================

if __name__ == "__main__":
    try:
        try:
            import requests
            from bs4 import BeautifulSoup
        except ImportError:
            print("[!] Installation des dependances...")
            os.system("pip3 install requests beautifulsoup4")
        
        crawler = JATHNIELCrawlerPro()
        crawler.run()
    except KeyboardInterrupt:
        print("\n\n👋 Au revoir!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erreur fatale: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
