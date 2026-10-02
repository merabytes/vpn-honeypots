#!/usr/bin/env python3
"""
download.py — Captura estática de un portal GlobalProtect (PAN-OS).

Descarga la página de logon del portal y todo lo que cuelga de ella: HTML, CSS,
JS, imágenes y los endpoints que el portal consulta. Guarda el resultado en
static_cache/ con la misma estructura de rutas que el original, que es lo que
sirve app.py.

Sin credenciales y sin payloads destructivos: sólo GET/POST pasivos.

Uso:
    python3 download.py                                  # host por defecto
    python3 download.py --host portal.miempresa.com
"""
import os
import re
import ssl
import json
import time
import hashlib
import argparse
import urllib.parse
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter

try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

# ─── Configuración ────────────────────────────────────────────────────────────
DEFAULT_HOST = os.environ.get("TARGET_HOST", "portal.example.com")
CACHE_DIR    = Path(__file__).parent / "static_cache"
TIMEOUT      = 20
DELAY        = 0.12

HEADERS_BASE = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
}

# ─── Semillas ─────────────────────────────────────────────────────────────────
# (method, path, post_data, save_key) — lo que define la pinta del portal y su
# fingerprint. Se guarda siempre, incluso con status != 200.
FINGERPRINT_ENDPOINTS = [
    ("GET",  "/global-protect/login.esp",           None, "global-protect/login.esp"),
    ("GET",  "/ssl-vpn/prelogin.esp",               None, "ssl-vpn/prelogin.esp"),
    ("GET",  "/global-protect/prelogin.esp",        None, "global-protect/prelogin.esp"),
    ("GET",  "/global-protect/getsoftwarepage.esp", None, "global-protect/getsoftwarepage.esp"),
    # Página de sesión caducada: el portal manda aquí (con ?code=N) cuando algo
    # falla a nivel de sesión. El índice del mensaje lo pone app.py.
    ("GET",  "/global-protect/logout.esp",          None, "global-protect/logout.esp"),
    # El 404 del frontal (141 B), tal cual lo devuelve cualquier ruta que no
    # exista. app.py lo usa como plantilla.
    ("GET",  "/nonexistent",                        None, "404.html"),
]

# Rutas que el portal pinta o enlaza y conviene tener aunque no salgan del HTML.
EXTRA_PATHS = [
    "/global-protect/portal/css/bootstrap.min.css",
    "/global-protect/portal/css/latofonts.css",
    "/global-protect/portal/css/login.css",
    "/global-protect/portal/css/ie10-viewport-bug-workaround.css",
    "/global-protect/portal/js/jquery.min.js",
    "/global-protect/portal/js/ie10-viewport-bug-workaround.js",
    "/global-protect/portal/images/favicon.ico",
    "/global-protect/portal/images/logo-pan-48525a.svg",
    "/global-protect/portal/images/logo-pan-48525a.png",
]

# Extensiones que merece la pena seguir desde CSS/JS.
ASSET_EXTS = {
    ".css", ".js", ".json", ".xml", ".htm", ".html",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
}

# Marcador con el que se sustituye el host capturado en el contenido textual.
# app.py lo cambia por el host de cada petición, así que la copia no lleva la
# identidad de nadie: sirve igual en el dominio original o en uno de laboratorio.
HOST_PLACEHOLDER = "{{HOST}}"

# Un path más largo que esto es una recursión, no un recurso.
MAX_PATH_LEN = 300

TEXT_CTYPES = ("text/", "application/json", "application/xml",
               "application/javascript")

session = requests.Session()
session.verify = False
session.headers.update(HEADERS_BASE)

CURRENT_HOST = ""


class _AdapterTLS(HTTPAdapter):
    """
    PAN-OS no negocia la renegociación segura de TLS (RFC 5746) y OpenSSL
    moderno corta la conexión con UNSAFE_LEGACY_RENEGOTIATION_DISABLED. curl
    pasa porque su OpenSSL lo permite; Python hay que decírselo.
    """

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


session.mount("https://", _AdapterTLS())


# ─── Helpers ──────────────────────────────────────────────────────────────────
def cache_path(rel: str) -> Path:
    """Convierte un path URL en la ruta de disco correspondiente.

    Sólo las rutas que terminan en «/» son directorios; una ruta sin extensión
    es un fichero, no una carpeta.
    """
    rel = rel.lstrip("/")
    p = CACHE_DIR / rel
    if rel == "" or rel.endswith("/"):
        p = p / "index.html"
    return p


def scrub(data: bytes, ctype: str = "") -> bytes:
    """Sustituye el host capturado por el marcador en contenido textual."""
    if not CURRENT_HOST:
        return data
    if ctype and not any(ctype.lower().startswith(t) for t in TEXT_CTYPES):
        return data
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    if CURRENT_HOST not in text:
        return data
    return text.replace(CURRENT_HOST, HOST_PLACEHOLDER).encode("utf-8")


def save(rel: str, content: bytes, ctype: str = "") -> Path:
    p = cache_path(rel)
    if p.is_dir():
        p = p / "index.html"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(scrub(content, ctype))
    print(f"  ✓ {rel}  ({len(content):,} B)  [{ctype.split(';')[0].strip()}]")
    return p


def fetch(method: str, url: str, data=None):
    try:
        if method.upper() == "POST":
            return session.post(url, data=data or {}, timeout=TIMEOUT,
                                allow_redirects=False)
        return session.get(url, timeout=TIMEOUT, allow_redirects=True)
    except Exception as e:
        print(f"  ✗ ERROR  {url}  → {e}")
        return None


def url_to_rel(url: str) -> str:
    """Path de una URL, con la query hasheada para no pisar ficheros distintos."""
    p = urllib.parse.urlparse(url)
    path = p.path or "/"
    if p.query:
        qhash = hashlib.md5(p.query.encode()).hexdigest()[:8]
        base, ext = os.path.splitext(path)
        path = f"{base}_{qhash}{ext}"
    return path


_REF_RE   = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+)["']""", re.I)
_URLFN_RE = re.compile(r"""url\(\s*["']?([^"')]+?)["']?\s*\)""", re.I)
_JSSTR_RE = re.compile(
    r"""["']([^"'\s]{3,200}?\.(?:css|js|json|xml|png|jpe?g|gif|ico|svg|bmp|webp|woff2?|ttf|eot))["']""",
    re.I,
)


def refs_from(text: str, kind: str) -> list:
    """URLs referenciadas por un HTML/CSS/JS, sin normalizar."""
    out = []
    if kind == "css":
        out += _URLFN_RE.findall(text)
    elif kind == "js":
        out += _JSSTR_RE.findall(text)
    else:  # html
        out += _REF_RE.findall(text)
        out += _URLFN_RE.findall(text)
    return out


def absolutize(raw: str, base_url: str, host: str = ""):
    """Normaliza una referencia a URL absoluta del mismo host, o None."""
    raw = raw.strip()
    if not raw or raw.startswith(("data:", "javascript:", "mailto:", "#", "blob:")):
        return None
    url = urllib.parse.urljoin(base_url, raw)
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https") or not p.path:
        return None
    # Sólo el host capturado: lo de terceros se deja apuntando fuera, como en el
    # original.
    if host and p.netloc != host:
        return None
    return url


def kind_of(ctype: str, path: str) -> str:
    ctype = (ctype or "").lower()
    if "css" in ctype or path.endswith(".css"):
        return "css"
    if "javascript" in ctype or path.endswith(".js"):
        return "js"
    if ("html" in ctype or "xml" in ctype
            or path.endswith((".htm", ".html", ".xml"))):
        return "html"
    return "other"


# ─── Descarga principal ───────────────────────────────────────────────────────
def download_all(host: str):
    global CURRENT_HOST
    CURRENT_HOST = host
    base_url = f"https://{host}"
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    meta: dict = {}
    seen: set = set()
    queue: list = []   # (url, kind)

    print(f"\n{'=' * 70}")
    print("  Palo Alto GlobalProtect — captura estática")
    print(f"  Host:  {host}")
    print(f"  Cache: {CACHE_DIR}")
    print(f"{'=' * 70}\n")

    # ── 1) Endpoints de fingerprint ──────────────────────────────────────────
    print("── Endpoints del portal ─────────────────────────────────────────")
    for method, path, data, save_key in FINGERPRINT_ENDPOINTS:
        url = f"{base_url}{path}"
        print(f"\n[{method}] {path}")
        r = fetch(method, url, data=data)
        if r is None:
            meta[save_key] = {"status": 0, "error": "connection_failed"}
            continue
        ctype = r.headers.get("Content-Type", "")
        print(f"  status={r.status_code}  ct={ctype.split(';')[0].strip()}")
        save(save_key, r.content, ctype)
        headers = {
            k: (scrub(v.encode(), "text/plain").decode()
                if isinstance(v, str) else v)
            for k, v in dict(r.headers).items()
        }
        meta[save_key] = {"status": r.status_code, "ctype": ctype,
                          "size": len(r.content), "headers": headers}
        seen.add(url)
        k = kind_of(ctype, path)
        if k in ("html", "css", "js"):
            queue.append((url, k))
        time.sleep(0.3)

    # ── 2) Rutas conocidas ───────────────────────────────────────────────────
    print("\n── Rutas conocidas ──────────────────────────────────────────────")
    for path in EXTRA_PATHS:
        url = f"{base_url}{path}"
        if url in seen:
            continue
        seen.add(url)
        r = fetch("GET", url)
        if r is None:
            continue
        ctype = r.headers.get("Content-Type", "")
        rel = url_to_rel(url)
        print(f"\n[GET] {path}  →  {r.status_code}")
        save(rel, r.content, ctype)
        meta[rel] = {"status": r.status_code, "ctype": ctype, "size": len(r.content),
                     "headers": {k: v for k, v in dict(r.headers).items()}}
        k = kind_of(ctype, path)
        if k in ("html", "css", "js") and r.status_code == 200:
            queue.append((url, k))
        time.sleep(0.2)

    # ── 3) Rastreo de assets (BFS: HTML → CSS → JS → imágenes/fuentes) ───────
    print("\n── Rastreo de assets referenciados ──────────────────────────────")
    pending: list = list(queue)
    queued = {u for u, _ in queue}
    crawled_hashes: set = set()
    while pending:
        page_url, kind = pending.pop(0)
        try:
            r = session.get(page_url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code != 200:
                continue
            text = r.content.decode("utf-8", errors="replace")
        except Exception:
            continue

        # Páginas que se enlazan a sí mismas generarían rutas infinitas; el hash
        # del contenido las corta.
        digest = hashlib.md5(r.content).hexdigest()
        if digest in crawled_hashes:
            continue
        crawled_hashes.add(digest)

        found = 0
        for raw in refs_from(text, kind):
            url = absolutize(raw, page_url, host)
            if url is None or url in seen:
                continue
            url_path = urllib.parse.urlparse(url).path
            if len(url_path) > MAX_PATH_LEN:
                continue
            ext = os.path.splitext(url_path)[1].lower()
            if ext not in ASSET_EXTS:
                continue
            seen.add(url)
            rr = fetch("GET", url)
            if rr is None or rr.status_code not in (200, 304):
                continue
            ctype = rr.headers.get("Content-Type", "")
            rel = url_to_rel(url)
            if cache_path(rel).exists():
                continue
            save(rel, rr.content, ctype)
            found += 1
            k2 = kind_of(ctype, url)
            if k2 in ("css", "js", "html") and url not in queued:
                queued.add(url)
                pending.append((url, k2))
            time.sleep(DELAY)
        if found:
            print(f"  ↑ {found} assets nuevos desde {page_url}")

    # ── 4) Metadata ──────────────────────────────────────────────────────────
    meta["_capture"] = {
        "host_placeholder": HOST_PLACEHOLDER,
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": len([f for f in CACHE_DIR.rglob("*") if f.is_file()]),
    }
    meta_file = CACHE_DIR / "_meta.json"
    with open(meta_file, "w") as f:
        json.dump(meta, f, indent=2, default=str)
    print(f"\n✓ Metadata en {meta_file}")

    files = [f for f in CACHE_DIR.rglob("*") if f.is_file() and f.name != "_meta.json"]
    total = sum(f.stat().st_size for f in files)
    print(f"\n{'=' * 70}")
    print(f"  Captura completada — {len(files)} archivos, {total / 1024:.1f} KB")
    print(f"{'=' * 70}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default=DEFAULT_HOST,
                    help=f"host a capturar (por defecto {DEFAULT_HOST})")
    args = ap.parse_args()
    download_all(args.host)


if __name__ == "__main__":
    main()
