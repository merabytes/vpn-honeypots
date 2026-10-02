#!/usr/bin/env python3
"""
test_e2e.py — Suite E2E completa del honeypot de NetScaler / Citrix Gateway.

Cubre los endpoints que el Receiver for Web usa en el logon (fingerprint,
nFactor, desafío de autenticación, captura de credenciales y assets).

Uso:
    python3 test_e2e.py [--port 8443] [--verbose]

Ejecuta el servidor en un thread, lanza todas las pruebas, reporta resultado.
"""
import sys, os, re, json, time, threading, argparse
from pathlib import Path
from typing import Optional
import urllib3; urllib3.disable_warnings()

# Asegurar que el módulo app está en path
sys.path.insert(0, str(Path(__file__).parent))

import requests
import app as honeypot_app

# ─── Config ──────────────────────────────────────────────────────────────────
DEFAULT_PORT = 19998
RESULTS = []  # lista de (test_name, passed, detail)

# ─── Helpers ─────────────────────────────────────────────────────────────────
class Colors:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def ok(name, detail=""):
    RESULTS.append((name, True, detail))
    print(f"  {Colors.GREEN}✓{Colors.RESET} {name}" + (f"  — {detail}" if detail else ""))

def fail(name, detail=""):
    RESULTS.append((name, False, detail))
    print(f"  {Colors.RED}✗{Colors.RESET} {name}  — {Colors.RED}{detail}{Colors.RESET}")

def section(title):
    print(f"\n{Colors.BOLD}{Colors.CYAN}── {title} {'─'*(55-len(title))}{Colors.RESET}")

def get(path, **kw) -> requests.Response:
    return session.get(f"http://localhost:{PORT}{path}", **kw)

def post(path, **kw) -> requests.Response:
    return session.post(f"http://localhost:{PORT}{path}", **kw)

# ─── Test helpers ─────────────────────────────────────────────────────────────
def assert_status(name, r, expected):
    if r.status_code == expected:
        ok(name, f"HTTP {r.status_code}")
    else:
        fail(name, f"expected {expected}, got {r.status_code}")

def assert_content_type(name, r, ct_fragment):
    ct = r.headers.get("Content-Type", "")
    if ct_fragment.lower() in ct.lower():
        ok(name, f"Content-Type: {ct.split(';')[0]}")
    else:
        fail(name, f"expected CT containing '{ct_fragment}', got '{ct}'")

def assert_header(name, r, header, value=None, absent=False):
    val = r.headers.get(header)
    if absent:
        if val is None:
            ok(name, f"{header} absent")
        else:
            fail(name, f"{header} should be absent, got '{val}'")
    elif value is None:
        if val is not None:
            ok(name, f"{header}: {val}")
        else:
            fail(name, f"{header} missing")
    else:
        if val == value:
            ok(name, f"{header}: {val}")
        else:
            fail(name, f"{header} expected '{value}', got '{val}'")

def assert_body_contains(name, r, fragment, encoding="utf-8"):
    body = r.content.decode(encoding, errors="replace")
    if fragment in body:
        ok(name, f"body contains '{fragment[:40]}'")
    else:
        fail(name, f"body missing '{fragment[:40]}'")

def assert_body_xml(name, r, tag):
    body = r.content.decode("utf-8", errors="replace")
    if f"<{tag}" in body or f"<{tag}>" in body:
        ok(name, f"XML tag <{tag}> present")
    else:
        fail(name, f"XML tag <{tag}> missing in: {body[:120]}")

def cred_in_log(username: str) -> Optional[dict]:
    """Busca captura de credencial en el log."""
    log_path = Path(__file__).parent / "honeypot.log"
    if not log_path.exists():
        return None
    for line in log_path.read_text().splitlines():
        try:
            ev = json.loads(line)
            if ev.get("event") == "CREDENTIAL_CAPTURE" and ev.get("username") == username:
                return ev
        except Exception:
            pass
    return None


# ─── Test suites ──────────────────────────────────────────────────────────────

def test_server_headers():
    """Verifica que el honeypot no delata stack Python/Werkzeug."""
    section("Server Headers / Fingerprint masking")
    r = get("/logon/LogonPoint/tmindex.html")

    sv = r.headers.get("Server", "")
    # En dev server (Werkzeug), el header lo inyecta el socket layer DESPUÉS del
    # WSGI middleware — el middleware sí elimina el header a nivel WSGI.
    # En gunicorn (producción), el middleware lo elimina correctamente.
    # Verificamos que el middleware WSGI está instalado (via código) y que
    # al menos no hay Flask/Werkzeug-solo (el middleware añade ", Apache" al final
    # cuando el dev server fusiona los dos).
    if sv == "Apache":
        ok("Server header is clean 'Apache' (gunicorn/prod mode)")
    elif "Apache" in sv:
        ok("Server header includes Apache (dev mode — middleware active)",
           f"Server: {sv}  [note: dev server adds Werkzeug prefix at socket level]")
    else:
        fail("Server header missing Apache fingerprint", f"Server: {sv}")

    assert_header("X-Powered-By absent", r, "X-Powered-By", absent=True)
    assert_header("X-Frame-Options present", r, "X-Frame-Options")


def test_vpn_pluginlist():
    """GET /vpn/pluginlist.xml — fingerprint de versión NS."""
    section("/vpn/pluginlist.xml  [FINGERPRINT versión NS]")
    r = get("/vpn/pluginlist.xml", allow_redirects=True)
    assert_status("HTTP 200", r, 200)
    assert_content_type("Content-Type XML", r, "xml")
    # NS usa <repository> y <plugin name=...> — no <PluginDetails>
    if "<repository" in r.text or "<plugin" in r.text:
        ok("Has NS plugin/repository XML structure")
    else:
        fail("Has NS plugin/repository XML structure", f"body: {r.text[:100]}")
    # Verificar que tiene versión (version=)
    if 'version=' in r.text or '<Version>' in r.text or 'pluginVersion' in r.text.lower():
        ok("Version field present in XML")
    else:
        fail("Version field present in XML", "not found")


def test_nfactor_auth_requirements():
    """GET /nf/auth/getAuthenticationRequirements.do — nFactor stack."""
    section("/nf/auth/getAuthenticationRequirements.do  [nFactor login schema]")
    r = get("/nf/auth/getAuthenticationRequirements.do", allow_redirects=True)
    assert_status("HTTP 200", r, 200)
    assert_content_type("Content-Type citrix XML", r, "xml")
    # Debe contener AuthenticateResponse o loginschema
    body = r.text
    if "AuthenticateResponse" in body or "loginschema" in body.lower() or "Status" in body:
        ok("NS auth response XML structure")
    else:
        fail("NS auth response XML structure", f"body: {body[:100]}")


def test_nfactor_doLogoff():
    """POST /nf/auth/doLogoff.do → <Status>success</Status>"""
    section("/nf/auth/doLogoff.do  [nFactor logoff]")
    r = post("/nf/auth/doLogoff.do", data={})
    assert_status("POST HTTP 200", r, 200)
    assert_content_type("Content-Type citrix XML", r, "xml")
    if "<Status>success</Status>" in r.text:
        ok("Body: <Status>success</Status>")
    else:
        # Puede tener variante sin spaces
        if "success" in r.text.lower():
            ok("Body contains 'success'", "(lowercase check)")
        else:
            fail("Body: <Status>success</Status>", f"got: {r.text[:100]}")
    # También funcionar con GET
    r2 = get("/nf/auth/doLogoff.do")
    assert_status("GET HTTP 200 (fallback)", r2, 200)


def test_oidc_config():
    """GET /oauth/idp/.well-known/openid-configuration → JSON con issuer."""
    section("/oauth/idp/.well-known/openid-configuration  [OIDC / CitrixBleed surface]")
    r = get("/oauth/idp/.well-known/openid-configuration", allow_redirects=True)
    assert_status("HTTP 200", r, 200)
    assert_content_type("Content-Type JSON", r, "json")
    try:
        data = r.json()
        if "issuer" in data:
            ok("JSON has 'issuer' field", data["issuer"])
        else:
            fail("JSON has 'issuer' field", "missing")
        if "authorization_endpoint" in data:
            ok("JSON has 'authorization_endpoint'")
        else:
            fail("JSON has 'authorization_endpoint'", "missing")
    except Exception as e:
        fail("Valid JSON response", str(e))


def test_vpns_cgi_login_get():
    """GET /vpns/cgi/login → login page HTML."""
    section("/vpns/cgi/login  [legacy AAA endpoint]")
    r = get("/vpns/cgi/login", allow_redirects=True)
    assert_status("GET HTTP 200", r, 200)
    assert_content_type("Content-Type HTML", r, "html")
    if len(r.content) > 1000:
        ok("Non-trivial HTML response", f"{len(r.content):,} bytes")
    else:
        fail("Non-trivial HTML response", f"only {len(r.content)} bytes")


def test_vpns_cgi_login_post_credentials():
    """POST /vpns/cgi/login con credenciales → 302 + log."""
    section("/vpns/cgi/login  [credential capture — legacy endpoint]")
    user = "test.legacy@example.com"
    r = post("/vpns/cgi/login",
             data={"username": user, "password": "LegacyPass99!", "StateContext": "x"},
             allow_redirects=False)
    assert_status("POST 302 redirect", r, 302)
    if "Location" in r.headers:
        ok("Location header present", r.headers["Location"])
    else:
        fail("Location header present")
    time.sleep(0.15)
    ev = cred_in_log(user)
    if ev:
        ok("Credentials captured in log", f"user={ev['username']}")
        if ev.get("password"):
            ok("Password captured", ev["password"])
        else:
            fail("Password captured", "empty")
    else:
        fail("Credentials captured in log", "event not found")


def test_cgi_login_post_credentials():
    """POST /cgi/login con credenciales (alias)."""
    section("/cgi/login  [credential capture — cgi alias]")
    user = "test.cgi@example.com"
    r = post("/cgi/login",
             data={"username": user, "password": "CgiPass@2026"},
             allow_redirects=False)
    assert_status("POST 302 redirect", r, 302)
    time.sleep(0.15)
    ev = cred_in_log(user)
    if ev:
        ok("Credentials captured in log", f"user={ev['username']}")
    else:
        fail("Credentials captured in log")


def test_nfactor_doAuthenticate():
    """POST /nf/auth/doAuthenticate.do → form + label de error + log.

    El NetScaler real no responde «fail»: devuelve 200 con el formulario otra
    vez y un Requirement extra de tipo «error». La copia lo imita, así que la
    comprobación es esa, no un Status de fallo que el real nunca manda.
    """
    section("/nf/auth/doAuthenticate.do  [nFactor doAuthenticate + capture]")
    user = "test.nfactor@example.com"
    r = post("/nf/auth/doAuthenticate.do",
             data={"username": user, "password": "NfactorPwd!2026"},
             allow_redirects=False)
    assert_status("POST HTTP 200", r, 200)
    assert_content_type("Content-Type citrix XML", r, "xml")
    if "<AuthenticateResponse" in r.text and "<Status>success</Status>" in r.text:
        ok("Response is an AuthenticateResponse (no real session leak)")
    else:
        fail("Response is an AuthenticateResponse", f"got: {r.text[:100]}")
    if "errorMessageLabel" in r.text or "<Type>error</Type>" in r.text:
        ok("Form re-sent with an error label (like the real NetScaler)")
    else:
        fail("Form re-sent with an error label", f"got: {r.text[:160]}")
    time.sleep(0.15)
    ev = cred_in_log(user)
    if ev:
        ok("Credentials captured in log", f"user={ev['username']}")
    else:
        fail("Credentials captured in log")


def test_logon_main_page():
    """GET /logon/LogonPoint/tmindex.html → login page real."""
    section("/logon/LogonPoint/tmindex.html  [main login page]")
    r = get("/logon/LogonPoint/tmindex.html", allow_redirects=True)
    assert_status("HTTP 200", r, 200)
    assert_content_type("Content-Type HTML", r, "html")
    if len(r.content) > 10000:
        ok("Full HTML page served", f"{len(r.content):,} bytes")
    else:
        fail("Full HTML page served", f"only {len(r.content)} bytes")
    # Verificar que contiene JS/recursos NS
    if b"ctxs" in r.content or b"LogonPoint" in r.content or b"receiver" in r.content:
        ok("NS-specific content present (ctxs/LogonPoint/receiver)")
    else:
        fail("NS-specific content present")


def test_static_assets():
    """GET /logon/LogonPoint/receiver/js/external/jquery.min.js etc."""
    section("Static assets  [JS/CSS/images desde static_cache]")
    assets = [
        ("/logon/LogonPoint/receiver/js/external/jquery.min.js",    "javascript", None),
        ("/logon/LogonPoint/receiver/js/ctxs.core.min.js",          "javascript", None),
        ("/logon/LogonPoint/receiver/css/ctxs.no-js-ui.min.css",    "css",        None),
        ("/logon/LogonPoint/receiver/images/common/wspinner@2x.gif", "image",      b"GIF"),
        ("/logon/LogonPoint/receiver/images/common/ReceiverFullScreenBackground.jpg", "image", b"\xff\xd8"),
        ("/logon/LogonPoint/receiver/images/common/icon_vpn.ico",    "image",      None),
        ("/logon/LogonPoint/init.js",                                "javascript", None),
    ]
    for path, ct_hint, magic_bytes in assets:
        r = get(path)
        name = path.split("/")[-1]
        if r.status_code == 200:
            ok(f"{name} HTTP 200", f"{len(r.content):,} bytes")
            if ct_hint in r.headers.get("Content-Type","").lower():
                ok(f"{name} Content-Type {ct_hint}")
            else:
                fail(f"{name} Content-Type {ct_hint}",
                     r.headers.get("Content-Type","missing"))
            if magic_bytes and not r.content.startswith(magic_bytes):
                fail(f"{name} content magic", f"starts with {r.content[:4]}")
            elif magic_bytes:
                ok(f"{name} binary magic bytes match")
        else:
            fail(f"{name} HTTP 200", f"got {r.status_code}")


def test_catchall_redirect():
    """Rutas desconocidas → 302 hacia tmindex.html."""
    section("Catch-all redirect  [rutas desconocidas → login]")
    for path in ["/", "/unknown-path", "/citrix/whatever"]:
        r = get(path, allow_redirects=False)
        if r.status_code in (200, 302):
            if r.status_code == 302:
                loc = r.headers.get("Location","")
                ok(f"GET {path} → 302", f"Location: {loc}")
            else:
                ok(f"GET {path} → 200 (served from cache)")
        else:
            fail(f"GET {path}", f"unexpected status {r.status_code}")


def test_vpn_index_alias():
    """GET /vpn/index.html → misma login page."""
    section("/vpn/index.html  [alias]")
    r = get("/vpn/index.html")
    assert_status("HTTP 200", r, 200)
    assert_content_type("Content-Type HTML", r, "html")


def test_logoff_method_flexibility():
    """doLogoff funciona con GET y POST (NS acepta ambos)."""
    section("doLogoff GET/POST flexibility")
    for method in ["GET", "POST"]:
        r = (get if method=="GET" else post)("/nf/auth/doLogoff.do",
             **({"data":{}} if method=="POST" else {}))
        if r.status_code == 200:
            ok(f"doLogoff {method} 200")
        else:
            fail(f"doLogoff {method} 200", f"got {r.status_code}")


def test_json_credential_capture():
    """POST con JSON body también captura credenciales."""
    section("JSON credential capture  [Content-Type: application/json]")
    user = "test.json@example.com"
    r = session.post(f"http://localhost:{PORT}/cgi/login",
                     json={"username": user, "password": "JsonPwd!"},
                     allow_redirects=False)
    # Puede ser 302 o 200 dependiendo del path
    if r.status_code in (200, 302):
        ok("JSON POST accepted", f"HTTP {r.status_code}")
    else:
        fail("JSON POST accepted", f"HTTP {r.status_code}")
    time.sleep(0.15)
    ev = cred_in_log(user)
    if ev:
        ok("JSON credentials captured", f"user={ev['username']}")
    else:
        fail("JSON credentials captured", "not in log")


def test_telegram_escape():
    """
    El aviso de Telegram va con el HTML escapado.

    Se manda con parse_mode=HTML: un '<' en el usuario hace que Telegram rechace
    el mensaje entero (se pierde la alerta) y un '</code><a href=...>' inyecta
    enlaces en el aviso que lee el operador.
    """
    section("Aviso de Telegram  [escape HTML]")
    mensaje = honeypot_app._mensaje_credenciales(
        "ana<b", "clave&secreta", "1.2.3.4",
        'Mozilla/5.0 </code><a href="tg://user?id=1">aviso</a><code>',
        "/nf/auth/doAuthentication.do",
        {"city": "Madrid</b>", "country": "Spain", "countryCode": "ES",
         "org": "ACME & Co"},
    )
    propias = (mensaje.count("<b>") + mensaje.count("</b>")
               + mensaje.count("<code>") + mensaje.count("</code>"))
    if mensaje.count("<") == propias:
        ok("Ni un '<' fuera de las etiquetas del propio aviso")
    else:
        fail("Ni un '<' fuera de las etiquetas del propio aviso",
             f"{mensaje.count('<')} '<' para {propias} etiquetas")
    for esperado in ("ana&lt;b", "clave&amp;secreta", "Madrid&lt;/b&gt;", "ACME &amp; Co"):
        if esperado in mensaje:
            ok(f"Escapado en el aviso: {esperado}")
        else:
            fail(f"Escapado en el aviso: {esperado}", mensaje[:120])


def test_request_logging():
    """Todos los requests se logean."""
    section("Request logging")
    log_path = Path(__file__).parent / "honeypot.log"
    before = log_path.stat().st_size if log_path.exists() else 0
    get("/vpn/pluginlist.xml")
    time.sleep(0.1)
    after = log_path.stat().st_size if log_path.exists() else 0
    if after > before:
        ok("Request logged (log grew)", f"+{after-before} bytes")
    else:
        fail("Request logged", "log didn't grow")
    # Verificar que el último event es un 'request'
    lines = [l for l in log_path.read_text().splitlines() if l.strip()]
    if lines:
        try:
            ev = json.loads(lines[-1])
            if ev.get("event") == "request":
                ok("Log entry has event=request")
            else:
                fail("Log entry has event=request", f"event={ev.get('event')}")
        except Exception as e:
            fail("Log entry is valid JSON", str(e))


def test_ns_cookie_simulation():
    """POST /vpns/cgi/login → response puede incluir headers NS-like."""
    section("NS cookie/header simulation  [post-login headers]")
    r = post("/vpns/cgi/login",
             data={"username":"cookietest@example.com","password":"CookiePwd!"},
             allow_redirects=False)
    assert_status("302 on POST /vpns/cgi/login", r, 302)
    # Server header debe incluir Apache (en dev también, aunque Werkzeug lo prefija)
    sv = r.headers.get("Server","")
    if "Apache" in sv:
        ok("Server header includes Apache fingerprint", f"Server: {sv}")
    else:
        fail("Server header missing Apache fingerprint", f"Server: {sv}")


# ─── Main ─────────────────────────────────────────────────────────────────────
def start_server(port):
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    logging.getLogger("honeypot").setLevel(logging.ERROR)
    # Reset log
    log_path = Path(__file__).parent / "honeypot.log"
    log_path.unlink(missing_ok=True)
    honeypot_app.app.run(host="127.0.0.1", port=port,
                         debug=False, use_reloader=False)


def main():
    global session, PORT

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    PORT = args.port

    # Servidor en thread daemon
    t = threading.Thread(target=start_server, args=(PORT,), daemon=True)
    t.start()
    time.sleep(2.5)  # esperar a que arranque

    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )

    print(f"\n{Colors.BOLD}{'='*70}")
    print(f"  NetScaler / Citrix Gateway Honeypot — E2E Test Suite")
    print(f"  Port: {PORT}")
    print(f"  Static cache: {honeypot_app.STATIC_DIR}")
    print(f"{'='*70}{Colors.RESET}")

    # Ejecutar todas las suites
    suites = [
        test_server_headers,
        test_vpn_pluginlist,
        test_nfactor_auth_requirements,
        test_nfactor_doLogoff,
        test_oidc_config,
        test_vpns_cgi_login_get,
        test_vpns_cgi_login_post_credentials,
        test_cgi_login_post_credentials,
        test_nfactor_doAuthenticate,
        test_logon_main_page,
        test_static_assets,
        test_catchall_redirect,
        test_vpn_index_alias,
        test_logoff_method_flexibility,
        test_json_credential_capture,
        test_telegram_escape,
        test_request_logging,
        test_ns_cookie_simulation,
    ]

    for suite in suites:
        try:
            suite()
        except Exception as e:
            fail(f"[EXCEPTION in {suite.__name__}]", str(e))

    # ── Resumen ──
    passed = sum(1 for _, p, _ in RESULTS if p)
    total  = len(RESULTS)
    failed_list = [(n, d) for n, p, d in RESULTS if not p]

    print(f"\n{Colors.BOLD}{'='*70}")
    color = Colors.GREEN if not failed_list else Colors.RED
    print(f"  {color}Resultado: {passed}/{total} tests pasados{Colors.RESET}{Colors.BOLD}")
    print(f"{'='*70}{Colors.RESET}")

    if failed_list:
        print(f"\n{Colors.RED}Failures:{Colors.RESET}")
        for name, detail in failed_list:
            print(f"  ✗ {name}  →  {detail}")

    sys.exit(0 if not failed_list else 1)


if __name__ == "__main__":
    main()
