#!/usr/bin/env python3
"""
Controlla lo stato dei domini in domains.json e aggiorna il file.
Usato dalla GitHub Action e può girare anche in locale.
"""

import asyncio
import json
import os
import random
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse, quote

import httpx

# ── Configurazioni ─────────────────────────────────────────────────────────────
TIMEOUT_S         = 20.0   # secondi per richiesta diretta
TRANSLATE_TIMEOUT = 40.0   # secondi per Google Translate
DELAY_BETWEEN     = 1.5    # pausa tra un dominio e l'altro
MAX_REDIRECTS     = 10

DOMAINS_FILE = os.environ.get("DOMAINS_FILE", "domains.json")

BROWSER_PROFILES = [
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 OPR/131.0.0.0",
        "lang": "it-IT,it;q=0.9,en;q=0.8",
    },
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        "lang": "it-IT,it;q=0.9,en;q=0.8",
    },
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0",
        "lang": "it-IT,it;q=0.9,en;q=0.8",
    },
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        "lang": "en-US,en;q=0.9,it;q=0.8",
    },
]

REFERERS = [
    "https://www.google.com/",
    "https://www.google.it/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
]


def get_headers() -> dict:
    p = random.choice(BROWSER_PROFILES)
    r = random.choice(REFERERS)
    return {
        "User-Agent": p["ua"],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": p["lang"],
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Referer": r,
        "Upgrade-Insecure-Requests": "1",
    }


def now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ── Check diretto con follow redirect ──────────────────────────────────────────
async def direct_check(client: httpx.AsyncClient, url: str) -> dict:
    """
    Segue i redirect manualmente e ritorna:
    { status, final_url } oppure { status: -1, error }
    """
    current_url = url
    visited = []

    for _ in range(MAX_REDIRECTS):
        try:
            res = await client.get(
                current_url,
                headers=get_headers(),
                follow_redirects=False,
                timeout=TIMEOUT_S,
            )
            visited.append({"url": current_url, "status": res.status_code})

            if res.status_code in (301, 302, 303, 307, 308):
                location = res.headers.get("location", "")
                if not location:
                    break
                if location.startswith("/"):
                    parsed = urlparse(current_url)
                    location = f"{parsed.scheme}://{parsed.netloc}{location}"
                elif not location.startswith("http"):
                    location = "https://" + location
                current_url = location
            else:
                break
        except httpx.TimeoutException:
            return {"status": -1, "error": "timeout", "final_url": current_url}
        except Exception as e:
            return {"status": -1, "error": str(e), "final_url": current_url}

    final_status = visited[-1]["status"] if visited else -1
    # Normalizza URL finale a origin + /
    try:
        p = urlparse(current_url)
        final_url = f"{p.scheme}://{p.netloc}/"
    except Exception:
        final_url = current_url

    return {"status": final_status, "final_url": final_url}


# ── Bypass Google Translate ────────────────────────────────────────────────────
def extract_new_url(html: str, original_url: str) -> str | None:
    # 1) <base href="...">
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

    # 2) <meta http-equiv="refresh" ...>
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


async def google_translate_proxy(client: httpx.AsyncClient, url: str) -> dict:
    proxy_url = f"https://translate.google.com/translate?sl=auto&tl=en&u={quote(url, safe='')}"
    try:
        res = await client.get(
            proxy_url,
            headers=get_headers(),
            follow_redirects=True,
            timeout=TRANSLATE_TIMEOUT,
        )
        if res.status_code != 200:
            return {"success": False, "error": f"translate status {res.status_code}"}
        html = res.text
        new_url = extract_new_url(html, url)
        if new_url and new_url != url:
            return {"success": True, "final_url": new_url}
        return {"success": False, "error": "nessun nuovo dominio trovato"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Processa un singolo sito ───────────────────────────────────────────────────
async def process_site(client: httpx.AsyncClient, name: str, config: dict) -> dict | None:
    url = config.get("full_url", "")
    if not url:
        return None

    print(f"[{name}] CHECK -> {url}")
    result = await direct_check(client, url)
    status = result["status"]
    final_url = result.get("final_url", url)

    # Redirect risolto: URL cambiato
    if final_url != url and status == 200:
        print(f"  ↳ Redirect a: {final_url}")
        return {**config, "full_url": final_url, "last_status": status, "time_change": now_str()}

    # 200 OK senza cambiamenti
    if status == 200:
        # Aggiorna comunque last_status se era diverso
        if config.get("last_status") != 200:
            return {**config, "last_status": 200, "time_change": now_str()}
        return None

    # Blocco → prova Google Translate
    if status in (403, 503, 429, -1):
        print(f"  ⚠️  Blocco (status {status}), provo Google Translate...")
        bypass = await google_translate_proxy(client, url)
        if bypass["success"]:
            new_url = bypass["final_url"]
            print(f"  ✅ Nuovo dominio: {new_url}")
            return {**config, "full_url": new_url, "last_status": 200, "time_change": now_str()}
        else:
            print(f"  ❌ Bypass fallito: {bypass['error']}")

    # Aggiorna solo lo status se cambiato
    if config.get("last_status") != status:
        return {**config, "last_status": status, "time_change": now_str()}

    return None


# ── Main ───────────────────────────────────────────────────────────────────────
async def main():
    # Carica domains.json
    if not os.path.exists(DOMAINS_FILE):
        print(f"❌ File non trovato: {DOMAINS_FILE}", file=sys.stderr)
        sys.exit(1)

    with open(DOMAINS_FILE, encoding="utf-8") as f:
        all_domains: dict = json.load(f)

    print(f"🔍 Avvio controllo di {len(all_domains)} domini\n")

    updated_count = 0
    async with httpx.AsyncClient() as client:
        for name, config in all_domains.items():
            updated = await process_site(client, name, config)
            if updated:
                all_domains[name] = updated
                updated_count += 1
            await asyncio.sleep(DELAY_BETWEEN)

    # Salva
    with open(DOMAINS_FILE, "w", encoding="utf-8") as f:
        json.dump(all_domains, f, indent=2, ensure_ascii=False)

    print(f"\n✅ {updated_count} domini aggiornati → {DOMAINS_FILE}")

    # Riepilogo
    print("\n--- Riepilogo ---")
    for name, config in all_domains.items():
        mark = "⚠️ " if config.get("last_status") not in (200, None) else "   "
        status = str(config.get("last_status", "?")).rjust(4)
        print(f"{mark}{name:<25} {status}  {config.get('full_url', '')}")


if __name__ == "__main__":
    asyncio.run(main())