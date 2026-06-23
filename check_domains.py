#!/usr/bin/env python3
"""
Controlla lo stato dei domini in domains.json e aggiorna il file.

- HTTP con curl_cffi (impersona Chrome → bypassa la maggior parte dei blocchi
  403 / Cloudflare che fermavano la vecchia versione basata su httpx).
- Risoluzione DNS via Google DNS-over-HTTPS (https://dns.google/resolve):
  l'IP ottenuto da Google viene forzato sulla connessione tramite
  CURLOPT_RESOLVE, così il check non dipende dal resolver del runner né da
  eventuali DNS poisoning.

Usato dalla GitHub Action, gira identico anche in locale.
"""

import json
import os
import random
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, quote

from curl_cffi import requests as cffi
from curl_cffi import CurlOpt

# Console UTF-8 anche su Windows (in CI Ubuntu è già utf-8).
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# ── Configurazioni ─────────────────────────────────────────────────────────────
TIMEOUT_S         = 20      # secondi per richiesta diretta
TRANSLATE_TIMEOUT = 40      # secondi per Google Translate
DELAY_BETWEEN     = 1.5     # pausa tra un dominio e l'altro
MAX_REDIRECTS     = 10
GOOGLE_DOH        = "https://dns.google/resolve"

# Gli header (User-Agent, sec-ch-ua, Accept, Accept-Language, ecc.) sono generati
# da curl_cffi in base al browser impersonato: sono coerenti con il fingerprint
# TLS, quindi molto più affidabili di header scritti a mano. Ruotiamo tra diversi
# browser reali: cambia insieme sia il TLS che il set di header.
IMPERSONATE_POOL = [
    "chrome146", "chrome145", "chrome142", "chrome136",
    "firefox147", "safari184", "edge101",
]


def pick_impersonate() -> str:
    return random.choice(IMPERSONATE_POOL)


# ── Proxy residenziali (solo come fallback sui domini bloccati) ──────────────────
# Alcuni siti rispondono 403 agli IP datacenter (es. i runner di GitHub). In quel
# caso ritentiamo il check tramite un proxy residenziale, scaricando SOLO gli header
# (stream=True, niente body) per non consumare banda — il piano ha un tetto di ~1GB/mese.
# Credenziali e lista possono essere sovrascritte da env (PROXY_USER/PROXY_PASS/PROXY_LIST).
PROXY_USER = os.environ.get("PROXY_USER", "jnwwkbvz")
PROXY_PASS = os.environ.get("PROXY_PASS", "z60r7lu63dm7")
_DEFAULT_PROXIES = [
    "31.59.20.176:6754", "31.56.127.193:7684", "45.38.107.97:6014",
    "38.154.203.95:5863", "198.105.121.200:6462", "64.137.96.74:6641",
    "198.23.243.226:6361", "38.154.185.97:6370", "142.111.67.146:5611",
    "191.96.254.138:6185",
]
PROXY_LIST = [p.strip() for p in os.environ.get("PROXY_LIST", "").split(",") if p.strip()] or _DEFAULT_PROXIES


def pick_proxy() -> str | None:
    if not PROXY_LIST:
        return None
    hostport = random.choice(PROXY_LIST)
    return f"http://{PROXY_USER}:{PROXY_PASS}@{hostport}"


DOMAINS_FILE = os.environ.get("DOMAINS_FILE", "domains.json")


# Pagine "anti-VPN"/interstitial: alcuni siti (es. mapple) reindirizzano gli IP
# datacenter/VPN/proxy a una pagina tipo disablevpn.* . Non va mai salvata come
# nuovo dominio, e su questi siti il proxy va EVITATO (peggiora le cose).
INTERSTITIAL_MARKERS = ("disablevpn", "disable-vpn", "vpncheck", "vpn-check", "blockvpn")


def is_interstitial(u: str) -> bool:
    host = (urlparse(u).hostname or "").lower()
    return any(m in host for m in INTERSTITIAL_MARKERS)


def now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ── Google DNS (DoH) ────────────────────────────────────────────────────────────
_dns_cache: dict[str, str | None] = {}


def resolve_google(host: str) -> str | None:
    """Risolve un hostname via Google DNS-over-HTTPS. Ritorna un IPv4 o None."""
    if host in _dns_cache:
        return _dns_cache[host]
    ip = None
    try:
        r = cffi.get(
            GOOGLE_DOH,
            params={"name": host, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=10,
            impersonate="chrome",
        )
        answers = [a["data"] for a in r.json().get("Answer", []) if a.get("type") == 1]
        ip = answers[0] if answers else None
    except Exception as e:
        print(f"  ⚠️  DoH fallita per {host}: {e}")
        ip = None
    _dns_cache[host] = ip
    return ip


def apply_google_dns(session: cffi.Session, url: str) -> None:
    """Forza sulla sessione l'IP Google per l'host dell'URL (CURLOPT_RESOLVE)."""
    host = urlparse(url).hostname
    if not host:
        return
    ip = resolve_google(host)
    if not ip:
        return
    entries = [f"{host}:443:{ip}".encode(), f"{host}:80:{ip}".encode()]
    try:
        session.curl.setopt(CurlOpt.RESOLVE, entries)
    except Exception as e:
        print(f"  ⚠️  RESOLVE setopt fallito per {host}: {e}")


# ── Check diretto con follow redirect manuale ───────────────────────────────────
def direct_check(session: cffi.Session, url: str, imp: str, proxy: str | None = None) -> dict:
    current_url = url
    visited = []

    for _ in range(MAX_REDIRECTS):
        try:
            if proxy:
                # Via proxy (banda a consumo): il DNS lo risolve il proxy. Chiediamo
                # solo il primo byte con l'header Range e in stream, così il server
                # risponde 206 con body ~vuoto → consumo minimo. Niente body letto.
                res = session.get(
                    current_url,
                    headers={"Range": "bytes=0-0"},
                    allow_redirects=False,
                    timeout=TIMEOUT_S,
                    impersonate=imp,
                    proxies={"http": proxy, "https": proxy},
                    stream=True,
                )
                status_code = res.status_code
                location = res.headers.get("location", "")
                res.close()  # chiude senza scaricare il body
                if status_code == 206:  # Partial Content = raggiungibile, come 200
                    status_code = 200
            else:
                apply_google_dns(session, current_url)
                res = session.get(
                    current_url,
                    allow_redirects=False,
                    timeout=TIMEOUT_S,
                    impersonate=imp,
                )
                status_code = res.status_code
                location = res.headers.get("location", "")

            visited.append({"url": current_url, "status": status_code})

            if status_code in (301, 302, 303, 307, 308):
                if not location:
                    break
                if location.startswith("/"):
                    p = urlparse(current_url)
                    location = f"{p.scheme}://{p.netloc}{location}"
                elif not location.startswith("http"):
                    location = "https://" + location
                current_url = location
            else:
                break
        except Exception as e:
            return {"status": -1, "error": str(e), "final_url": current_url}

    final_status = visited[-1]["status"] if visited else -1
    try:
        p = urlparse(current_url)
        final_url = f"{p.scheme}://{p.netloc}/"
    except Exception:
        final_url = current_url

    return {"status": final_status, "final_url": final_url}


# ── Bypass Google Translate (ultima spiaggia) ───────────────────────────────────
def extract_new_url(html: str, original_url: str) -> str | None:
    m = re.search(r'<base[^>]+href=["\']([^"\']+)["\']', html, re.I)
    if m:
        href = m.group(1)
        if not href.startswith("http"):
            href = "https://" + href
        try:
            p = urlparse(href)
            return f"{p.scheme}://{p.netloc}/"
        except Exception:
            pass

    m = re.search(
        r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\']+)["\']',
        html, re.I,
    )
    if m:
        redirect = m.group(1)
        if not redirect.startswith("http"):
            base = urlparse(original_url)
            redirect = f"{base.scheme}://{base.netloc}{redirect}"
        try:
            p = urlparse(redirect)
            return f"{p.scheme}://{p.netloc}/"
        except Exception:
            pass

    return None


def google_translate_proxy(session: cffi.Session, url: str, imp: str) -> dict:
    proxy_url = f"https://translate.google.com/translate?sl=auto&tl=en&u={quote(url, safe='')}"
    try:
        apply_google_dns(session, proxy_url)
        res = session.get(
            proxy_url,
            allow_redirects=True,
            timeout=TRANSLATE_TIMEOUT,
            impersonate=imp,
        )
        if res.status_code != 200:
            return {"success": False, "error": f"translate status {res.status_code}"}
        new_url = extract_new_url(res.text, url)
        if new_url and new_url != url:
            return {"success": True, "final_url": new_url}
        return {"success": False, "error": "nessun nuovo dominio trovato"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Processa un singolo sito ────────────────────────────────────────────────────
def process_site(session: cffi.Session, name: str, config: dict) -> dict | None:
    url = config.get("full_url", "")
    if not url:
        return None

    imp = pick_impersonate()
    print(f"[{name}] CHECK -> {url}  ({imp})")
    result = direct_check(session, url, imp)
    status = result["status"]
    final_url = result.get("final_url", url)
    checked = now_iso()

    # Pagina anti-VPN: tieni l'URL originale, niente proxy, registra solo lo status.
    if is_interstitial(final_url):
        print(f"  🛡️  Pagina anti-VPN ({final_url}) → mantengo {url}")
        if config.get("last_status") != status:
            return {**config, "last_status": status, "time_change": now_str(), "last_check": checked}
        return None

    # Bloccato dall'IP datacenter? Ritenta UNA volta via proxy residenziale
    # (solo header, Range piccolo → poca banda).
    if status in (403, 503, 429, -1):
        proxy = pick_proxy()
        if proxy:
            host = proxy.split("@")[-1]
            print(f"  ⚠️  Blocco (status {status}), ritento via proxy {host}...")
            pres = direct_check(session, url, imp, proxy=proxy)
            p_final = pres.get("final_url", url)
            if is_interstitial(p_final):
                print(f"  🛡️  Proxy → pagina anti-VPN, ignoro e mantengo {url}")
            elif pres["status"] not in (403, 503, 429, -1):
                print(f"  ✅ Proxy OK: status {pres['status']}")
                result, status = pres, pres["status"]
                final_url = p_final

    # Redirect risolto: URL cambiato
    if final_url != url and status == 200:
        print(f"  ↳ Redirect a: {final_url}")
        return {**config, "full_url": final_url, "last_status": status,
                "time_change": now_str(), "last_check": checked}

    # 200 OK
    if status == 200:
        if config.get("last_status") != 200:
            return {**config, "last_status": 200, "time_change": now_str(), "last_check": checked}
        return None

    # Blocco → prova Google Translate
    if status in (403, 503, 429, -1):
        print(f"  ⚠️  Blocco (status {status}), provo Google Translate...")
        bypass = google_translate_proxy(session, url, imp)
        if bypass["success"]:
            new_url = bypass["final_url"]
            print(f"  ✅ Nuovo dominio: {new_url}")
            return {**config, "full_url": new_url, "last_status": 200,
                    "time_change": now_str(), "last_check": checked}
        print(f"  ❌ Bypass fallito: {bypass['error']}")

    # Aggiorna solo lo status se cambiato
    if config.get("last_status") != status:
        return {**config, "last_status": status, "time_change": now_str(), "last_check": checked}

    return None


# ── Main ────────────────────────────────────────────────────────────────────────
def main():
    if not os.path.exists(DOMAINS_FILE):
        print(f"❌ File non trovato: {DOMAINS_FILE}", file=sys.stderr)
        sys.exit(1)

    with open(DOMAINS_FILE, encoding="utf-8") as f:
        all_domains: dict = json.load(f)

    print(f"🔍 Avvio controllo di {len(all_domains)} domini (curl_cffi + Google DNS)\n")

    updated_count = 0
    session = cffi.Session()
    try:
        for name, config in all_domains.items():
            try:
                updated = process_site(session, name, config)
            except Exception as e:
                print(f"  ❌ Errore su {name}: {e}")
                updated = None
            if updated:
                all_domains[name] = updated
                updated_count += 1
            time.sleep(DELAY_BETWEEN)
    finally:
        session.close()

    with open(DOMAINS_FILE, "w", encoding="utf-8") as f:
        json.dump(all_domains, f, indent=2, ensure_ascii=False)

    print(f"\n✅ {updated_count} domini aggiornati → {DOMAINS_FILE}")

    print("\n--- Riepilogo ---")
    for name, config in all_domains.items():
        mark = "⚠️ " if config.get("last_status") not in (200, None) else "   "
        status = str(config.get("last_status", "?")).rjust(4)
        print(f"{mark}{name:<25} {status}  {config.get('full_url', '')}")


if __name__ == "__main__":
    main()
