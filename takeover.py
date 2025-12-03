#!/usr/bin/env python3
import argparse
import json
import re
import sys
import time
import os
from urllib.parse import urlparse, urljoin, unquote, parse_qsl
import requests
from bs4 import BeautifulSoup
from bs4 import FeatureNotFound
from collections import defaultdict
import tldextract
import filelock
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import html as html_lib
import subprocess
import shlex

# =====================
# Configuration
# =====================
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1378828643475919009/bmhoZjOGGByjuVvbJayIF85EE3rViuzV9rDb6o0lj8tsL4Phr1PZK8rl9bRyfhF27bZj"
REQUEST_DELAY = 1.3  # seconds
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
ALL_DOMAINS_FILE = "all_domains.txt"
DOMAIN_SOURCES_FILE = "domain_sources.json"
AVAILABLE_RESULTS_FILE = "available_results.jsonl"
MAX_RETRIES = 3

VERCEL_TOKENS = [
    "0WICViJV21JoFIfB1HzNbzuq", "1OGvLezoABXlYiFendTnedlr", "uNTojeAlsxrNKR9AMfEPVpgX",
    "HbTVHP6FfkeNt82ZgTmDcRDk", "bPmMR624UgYJwLkXA0UUlmID", "I7UWycckrCySfzNxQPKypAMp",
    "86bhDMnWhmPbVQxzKxf0VQv3", "WgxM22g9xXnZddRyPETpTHSv", "iFf9FwPqR8I30WRtovkrU4td",
    "LyW5c8yrpOWlsqECoa7zKOXM", "YvqYVGBJwMtHsJUp0qhTE1QU", "pqGhvZNElv5DIMdEEZYgYcST",
    "4H4PTKPaDcnhDUbxVIwNU98a", "ugmj1qN8FZVFjIoDVqQXbqS9", "uiibSp8yponv9jg5aqZ4Ud4U",
    "zLcMyb89reoSb8XBgBATAsoM", "i6vtNYvwB5iJXUcubyzi8gJr", "YVRIuqB9B1Pz2VrDEtdJZuh6",
    "d5QN9gFZZxY0NGFrXIpRr1uI", "voe9l3TAzn8uRmvLhmuE2Xeh", "L9vVtqryvYCUAyewCmRSe1og",
    "XNqfhp2dTOHfYNla5jsnQQue", "8FazjfDfW4Xqtd4nz4XPvbju", "E6EbvGdJDrkgUyZxOIPguWJO",
    "GUSdFQPmM7Czu46kZ9W0upy6", "JDUW70GTZp6U9g1fplpKLDf2", "JhBVCAJJonQGx3VZ0VpqKiBr",
    "NtOYJ4ODgTBU9fZ9KygCTAvG", "PHnjlanfk0iqNGSC8E1ESsOh", "PoA0MjRTfWUVsLwopN0QwRRv",
    "UTuCwfUp61q33HG582vhEmgZ", "b0eEcwqiQ2Z6aGbiPXaYkdEM", "cxYzpUOeMAvF8iBaDtL5p0cb",
    "dFUJoKYKFhGBBadVRMRhLSlC", "daAEvGd01wCJM4fv0gVXaxNI", "drdJH1YCsiqYnkC6vVSSaZ8N",
    "fHUY8O1oyqJoNHs8FGHHKzkF", "fhjnx8DL47Avi4it6k2WZqv2", "fUsScyhsRSIet14tiHyv79GH",
    "g5TYFyPAlpWWa7B3Qeu7COOP", "lQSxtkdBl75tY9tGjJjlW0ao", "sipZdxvA6YjMJntgQwcM9LOI",
    "wD9KaYH76ox2lqF9KA70fh2c"
]

EXCLUDE_DOMAINS = [
    'google.com','schema.org','facebook.com','twitter.com','github.blog',
    'amazonaws.com','github.com','linkedin.com','zoom.com','gitlab.com',
    'w3.org','meta.com','cloudflare.com','amazon.com','wordpress.com'
]

TAG_ATTRS = [
    ('a', 'href'), ('area', 'href'),
    ('form', 'action'), ('input', 'formaction'), ('button', 'formaction'),
    ('meta', 'content'),
    ('link', 'href'),
    ('script', 'src'),
    ('img', 'src'), ('img', 'srcset'), ('img', 'data-src'),
    ('source', 'src'), ('source', 'srcset'),
    ('video', 'src'), ('video', 'poster'),
    ('audio', 'src'),
    ('track', 'src'),
    ('iframe', 'src'),
    ('embed', 'src'),
    ('object', 'data'),
    ('use', 'xlink:href'),
]

META_URLY = {'canonical','og:url','og:image','twitter:url','twitter:image'}
WRAP_CHARS = ' \'"()[]{}<>,;'
DOMAIN_RE = re.compile(r'(?<!@)\b((?:[a-z0-9-]+\.)+[a-z]{2,})(?!\w)', re.I)
SRCSET_SPLIT_RE = re.compile(r'\s*,\s*')
SKIP_SCHEMES = {'javascript','data','blob','about','chrome','mailto','tel'}


class DomainExtractor:
    def __init__(self, debug=False):
        self.tokens = VERCEL_TOKENS
        self.current_token_index = 0
        self.exclude_domains = set(EXCLUDE_DOMAINS)
        self.domain_sources = defaultdict(list)
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT, 'Accept-Language': 'en'})
        retries = Retry(total=3, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504))
        self.session.mount("http://", HTTPAdapter(max_retries=retries))
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

        self.lock = filelock.FileLock(f"{ALL_DOMAINS_FILE}.lock")
        self.scanned_domains = self._load_persistent_domains()
        self.failed_checks = set()

        self.results_lock = filelock.FileLock(f"{AVAILABLE_RESULTS_FILE}.lock")

        self.debug = debug

    def _load_persistent_domains(self):
        if not os.path.exists(ALL_DOMAINS_FILE):
            return set()
        try:
            with self.lock:
                with open(ALL_DOMAINS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    return {line.strip() for line in f if line.strip()}
        except Exception:
            return set()

    def _add_persistent_domain(self, domain):
        try:
            with self.lock:
                with open(ALL_DOMAINS_FILE, 'a', encoding='utf-8', errors='ignore') as f:
                    f.write(f"{domain}\n")
            return True
        except Exception:
            return False

    def get_root_domain(self, domain):
        ext = tldextract.extract(domain)
        if not ext.domain or not ext.suffix:
            return None
        return f"{ext.domain}.{ext.suffix}".lower()

    def is_valid_domain(self, domain):
        ext = tldextract.extract(domain)
        return bool(ext.domain and ext.suffix)

    def clean_domain(self, domain):
        if not domain:
            return None

        if '://' in domain:
            domain = urlparse(domain).netloc or domain

        if '@' in domain:
            domain = domain.split('@', 1)[-1]

        if ':' in domain:
            domain = domain.split(':', 1)[0]

        domain = domain.strip('[]')
        domain = re.sub(r'<[^>]+>', '', domain)
        domain = re.sub(r'[^a-zA-Z0-9.-]', '', domain)

        if not self.is_valid_domain(domain):
            return None

        # EXTREME fake-extension filter (filenames masquerading as domains)
        fake_exts = {
            "zip","rar","7z","gz","bz2","xz","tar","tgz","lz","lz4",
            "iso","img","dmg","bin","msi","exe","dll","so","deb","rpm",
            "apk","ipa","jar","war","ear",
            "pdf","doc","docx","dot","dotx","rtf","odt",
            "xls","xlsx","xlsm","ods","csv","tsv",
            "ppt","pptx","pps","ppsx","odp",
            "txt","log","cfg","conf","ini","properties","yml","yaml","toml",
            "json","xml",
            "html","htm","shtml","xhtml",
            "css","less","scss","sass",
            "js","mjs","cjs","ts","tsx","jsx",
            "map",
            "jpg","jpeg","png","gif","bmp","tif","tiff","webp","heic","ico","svg","psd","ai","eps",
            "mp3","wav","flac","ogg","oga","m4a","aac","wma",
            "mp4","m4v","mkv","avi","mov","wmv","flv","webm",
            "3gp","3g2",
            "swf","fla",
            "db","sql","sqlite","sqlite3","mdb","accdb",
            "bak","old","orig",
            "tmp","temp","cache",
            "dat","pak",
            "ps","eps","ai","indd",
            "apk","obb",
            "crt","pem","key","der","pfx","p12",
            "asc","sig",
            "rar","part",
        }
        parts = domain.lower().split(".")
        if len(parts) >= 2 and parts[-1] in fake_exts:
            return None

        root = self.get_root_domain(domain)
        return root.lower() if root else None

    def _decode_url_like(self, raw):
        if raw is None:
            return None
        s = str(raw)
        s = html_lib.unescape(s)
        s = s.replace(r'\"', '"').replace(r"\'", "'")
        try:
            s = unquote(unquote(s))
        except Exception:
            pass
        return s.strip(WRAP_CHARS)

    def _get_base_url(self, response_url, soup):
        base = soup.find('base', href=True)
        if base:
            try:
                return urljoin(response_url, base['href'])
            except Exception:
                return response_url
        return response_url

    def _domains_from_value(self, value, base_url, attr_name):
        results = set()
        if not value:
            return results

        decoded = self._decode_url_like(value)
        if not decoded:
            return results

        # Handle srcset lists
        if attr_name in ('srcset', 'data-srcset'):
            for part in SRCSET_SPLIT_RE.split(decoded):
                cand = (part.strip().split()[0] if part.strip() else '')
                results |= self._domains_from_value(cand, base_url, 'src')
            return results

        # Resolve absolute URL
        abs_url = urljoin(base_url, decoded)
        parsed = urlparse(abs_url if '://' in abs_url else f'http://{abs_url}')

        if parsed.scheme and parsed.scheme.lower() in SKIP_SCHEMES:
            return results

        # 1) Primary domain
        if parsed.netloc:
            dom = self.clean_domain(parsed.netloc)
            if dom:
                results.add(dom)

        # 2) Embedded domains in path/query/fragment
        try:
            qs_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        except Exception:
            qs_pairs = []

        path_parts = [parsed.path, parsed.fragment] + [v for _, v in qs_pairs]

        for part in path_parts:
            if not part:
                continue
            dec = self._decode_url_like(part)
            for m in DOMAIN_RE.findall(dec):
                dom = self.clean_domain(m)
                if dom:
                    results.add(dom)

        return results

    def extract_domains_from_html(self, html, response_url):
        try:
            soup = BeautifulSoup(html, 'lxml')
        except FeatureNotFound:
            soup = BeautifulSoup(html, 'html.parser')

        base_url = self._get_base_url(response_url, soup)
        found = set()

        for tag, attr in TAG_ATTRS:
            for el in soup.find_all(tag):
                if attr not in el.attrs:
                    continue

                if tag == 'meta' and attr == 'content':
                    name = (el.get('name') or el.get('property') or el.get('http-equiv') or '').lower()
                    content = self._decode_url_like(el.get('content'))

                    if name == 'refresh' and content and 'url=' in content.lower():
                        target = content.split('=', 1)[-1].strip()
                        found |= self._domains_from_value(target, base_url, 'content')
                        continue

                    if name in META_URLY or 'og:' in name or 'twitter:' in name:
                        found |= self._domains_from_value(el.get('content'), base_url, 'content')
                        continue

                val = el.get(attr)

                if attr == 'srcset':
                    parts = SRCSET_SPLIT_RE.split(val or '')
                    for p in parts:
                        cand = (p.strip().split()[0] if p.strip() else '')
                        found |= self._domains_from_value(cand, base_url, attr)
                else:
                    found |= self._domains_from_value(val, base_url, attr)

        return found

    def should_skip_domain(self, domain, source_domain):
        if not domain:
            return True
        if any(domain.endswith(f".{excl}") or domain == excl for excl in self.exclude_domains):
            return True
        if domain == source_domain or domain.endswith(f".{source_domain}"):
            return True
        return False

    def process_url(self, url):
        try:
            url = self.normalize_url(url)
            source_domain = self.get_root_domain(urlparse(url).netloc)
            if not source_domain:
                return set()

            print(f"🔍 Processing: {url}")

            try:
                response = self.session.get(url, timeout=25)
                response.raise_for_status()
            except requests.RequestException as e:
                print(f"⚠️ Failed to fetch {url}: {e}")
                return set()

            domains = self.extract_domains_from_html(response.text, response.url)
            new_domains = set()

            for dom in domains:
                root_domain = self.get_root_domain(dom)
                if root_domain and not self.should_skip_domain(root_domain, source_domain) and root_domain not in self.scanned_domains:
                    new_domains.add(root_domain)
                    if url not in self.domain_sources[root_domain]:
                        self.domain_sources[root_domain].append(url)

            if self.debug:
                print(f"   • extracted: {len(domains)}, new: {len(new_domains)}")

            return new_domains

        except Exception as e:
            print(f"⚠️ Error processing {url}: {e}")
            return set()

    def get_current_token(self):
        return self.tokens[self.current_token_index]

    def rotate_token(self):
        self.current_token_index = (self.current_token_index + 1) % len(self.tokens)
        print(f"🔄 Rotated token → {self.current_token_index + 1}/{len(self.tokens)}")

    def normalize_url(self, url):
        url = (url or '').strip()
        if not url.startswith(('http://', 'https://')):
            return f'http://{url}'
        return url

    def whois_available(self, domain):
        try:
            cmd = f'whois {shlex.quote(domain)}'
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=6).decode(errors="ignore")
            if ("No match for domain" in out or 
                "NOT FOUND" in out or 
                "Status: free" in out):
                return True
        except Exception:
            pass
        return False

    def check_domain_availability(self, domain):
        root_domain = self.get_root_domain(domain)
        if not root_domain or not self.is_valid_domain(root_domain):
            return False

        if root_domain in self.scanned_domains:
            return False

        current_scanned = self._load_persistent_domains()
        if root_domain in current_scanned:
            self.scanned_domains.add(root_domain)
            return False

        for attempt in range(MAX_RETRIES):
            try:
                url = f"https://api.vercel.com/v4/domains/status?name={root_domain}"
                headers = {"Authorization": f"Bearer {self.get_current_token()}"}
                response = self.session.get(url, headers=headers, timeout=15)

                if response.status_code == 429:
                    self.rotate_token()
                    time.sleep(REQUEST_DELAY)
                    continue

                response.raise_for_status()
                data = response.json()

                if self._add_persistent_domain(root_domain):
                    self.scanned_domains.add(root_domain)

                return data.get('available', False)

            except requests.RequestException as e:
                print(f"⚠️ Check failed for {root_domain}: {e}")
                time.sleep(REQUEST_DELAY * (attempt + 1))

        print(f"🔍 WHOIS fallback for {root_domain}…")
        time.sleep(1.2)

        if self.whois_available(root_domain):
            self.failed_checks.add(root_domain)
            return True

        self.failed_checks.add(root_domain)
        return False

    def send_discord_alert(self, domain, source_url):
        try:
            self.session.post(DISCORD_WEBHOOK, json={
                "content": f"🚨 Domain available: `{domain}`\nFound on: {source_url}",
                "username": "DomainBot"
            }, timeout=10)
            print(f"📢 Alert sent for {domain}")
        except requests.RequestException as e:
            print(f"⚠️ Failed to send Discord alert: {e}")

    def _save_domain_sources(self):
        try:
            with open(DOMAIN_SOURCES_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.domain_sources, f, indent=2)
        except Exception as e:
            print(f"⚠️ Failed saving {DOMAIN_SOURCES_FILE}: {e}")

    def _log_available_domain(self, domain):
        # Log available domain + sources to JSONL so the web UI can read it.
        record = {
            "domain": domain,
            "sources": self.domain_sources.get(domain, []),
            "timestamp": time.time()
        }
        try:
            with self.results_lock:
                with open(AVAILABLE_RESULTS_FILE, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(record) + "\n")
        except Exception as e:
            print(f"⚠️ Failed logging available domain {domain}: {e}")

    def process_domains(self, domains_file=None, input_stream=None):
        urls = self._read_input(domains_file, input_stream)
        new_domains = set()

        for url in urls:
            extracted = self.process_url(url)
            if extracted:
                new_domains.update(extracted)

        self._save_domain_sources()
        self._check_new_domains(new_domains)

    def _read_input(self, domains_file, input_stream):
        if domains_file:
            with open(domains_file, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        elif input_stream:
            return [line.strip() for line in input_stream if line.strip()]
        raise ValueError("No valid input provided")

    def _check_new_domains(self, domains):
        for domain in sorted(domains):
            time.sleep(REQUEST_DELAY)
            if self.check_domain_availability(domain):
                for source_url in self.domain_sources.get(domain, []):
                    self.send_discord_alert(domain, source_url)
                self._log_available_domain(domain)


def main():
    parser = argparse.ArgumentParser(description='Domain Availability Checker (tag-attribute only)')
    parser.add_argument('-i', '--input', help='Input file containing URLs/domains')
    parser.add_argument('--debug', action='store_true', help='Verbose extraction logs')
    args = parser.parse_args()

    extractor = DomainExtractor(debug=args.debug)

    if args.input:
        extractor.process_domains(domains_file=args.input)
    elif not sys.stdin.isatty():
        extractor.process_domains(input_stream=sys.stdin)
    else:
        print("Error: No input provided. Use -i or pipe input.")
        sys.exit(1)


if __name__ == '__main__':
    main()
