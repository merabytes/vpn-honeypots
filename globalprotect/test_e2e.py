#!/usr/bin/env python3
"""
test_e2e.py — Suite E2E del honeypot de Palo Alto GlobalProtect.

Levanta la app en un hilo y comprueba lo que un visitante (o un analista) vería:
la cadena de URLs del portal, la página de logon, sus assets, los endpoints
prelogin, la página de sesión caducada, la captura de credenciales y el 404.

Uso:
    .venv/bin/python test_e2e.py [--port 19998]
"""
import re
import sys
import json
import time
import threading
import argparse
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings()

sys.path.insert(0, str(Path(__file__).parent))

import app as honeypot_app

# ─── Config ──────────────────────────────────────────────────────────────────
DEFAULT_PORT = 19998
RESULTS = []


class Colors:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
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
    print(f"\n{Colors.BOLD}{Colors.CYAN}── {title} {'─' * (52 - len(title))}{Colors.RESET}")


def get(path, **kw):
    return session.get(f"http://localhost:{PORT}{path}", **kw)


def post(path, **kw):
    return session.post(f"http://localhost:{PORT}{path}", **kw)


def cred_in_log(username):
    log_path = Path(__file__).parent / "honeypot.log"
    if not log_path.exists():
        return None
    for line in log_path.read_text().splitlines():
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get("event") == "CREDENTIAL_CAPTURE" and ev.get("username") == username:
            return ev
    return None


# ─── Suites ───────────────────────────────────────────────────────────────────
def test_headers():
    """El portal real no manda Server y sí Date + cabeceras de seguridad."""
    section("Cabeceras  [sin Server, con Date]")
    r = get("/global-protect/login.esp")
    if "Server" not in r.headers:
        ok("Sin cabecera Server (como el portal real)")
    else:
        fail("Sin cabecera Server", f"Server: {r.headers['Server']}")
    for h in ("Date", "X-Frame-Options", "Strict-Transport-Security",
              "X-Content-Type-Options", "Content-Security-Policy"):
        if h in r.headers:
            ok(f"{h} presente", r.headers[h][:40])
        else:
            fail(f"{h} presente")
    if r.headers.get("X-Frame-Options") == "DENY":
        ok("X-Frame-Options: DENY")
    else:
        fail("X-Frame-Options: DENY", r.headers.get("X-Frame-Options", "ausente"))
    if "SESSID=" in r.headers.get("Set-Cookie", ""):
        ok("Reparte cookie SESSID")
    else:
        fail("Reparte cookie SESSID", r.headers.get("Set-Cookie", "ausente"))


def test_root_redirect():
    """GET / → 302 a la página de logon, con el salto por JavaScript."""
    section("Raíz  [/ → login.esp]")
    r = get("/", allow_redirects=False)
    if r.status_code == 302:
        ok("GET / → 302")
    else:
        fail("GET / → 302", f"got {r.status_code}")
    if r.headers.get("Location") == "/global-protect/login.esp":
        ok("Location: /global-protect/login.esp")
    else:
        fail("Location", r.headers.get("Location", "ausente"))
    if b"window.location" in r.content:
        ok("Cuerpo con redirección JavaScript (como el real)")
    else:
        fail("Cuerpo con redirección JavaScript")


def test_login_page():
    """La página de logon: formulario, csrf-token y usuario/contraseña."""
    section("Página de logon  [/global-protect/login.esp]")
    r = get("/global-protect/login.esp")
    if r.status_code == 200:
        ok("HTTP 200")
    else:
        fail("HTTP 200", f"got {r.status_code}")
    if "text/html" in r.headers.get("Content-Type", ""):
        ok("Content-Type HTML", r.headers.get("Content-Type"))
    else:
        fail("Content-Type HTML", r.headers.get("Content-Type", "?"))
    for fragmento in ('id="login_form"', 'name="user"', 'name="passwd"',
                      'name="csrf-token"', "GlobalProtect Portal"):
        if fragmento in r.text:
            ok(f"Página con {fragmento}")
        else:
            fail(f"Página con {fragmento}")
    if "{{HOST}}" not in r.text:
        ok("Sin marcadores de host sin sustituir")
    else:
        fail("Sin marcadores de host sin sustituir")


def test_token_rota():
    """El csrf-token cambia en cada visita, como en el portal real."""
    section("csrf-token  [uno nuevo en cada GET]")
    tokens = set()
    for _ in range(3):
        r = get("/global-protect/login.esp")
        m = re.search(r'name="csrf-token" value="([^"]+)"', r.text)
        if m:
            tokens.add(m.group(1))
    if len(tokens) == 3:
        ok("Tres peticiones, tres tokens distintos")
    else:
        fail("Tres peticiones, tres tokens distintos", f"{len(tokens)} únicos")
    if all(re.match(r"^[\w-]{28}:\d{13}$", t) for t in tokens):
        ok("Formato del token como el de PAN-OS", next(iter(tokens))[:20] + "…")
    else:
        fail("Formato del token como el de PAN-OS", str(sorted(tokens))[:80])


def test_assets():
    """CSS, JS, imágenes y fuentes del portal."""
    section("Assets  [CSS/JS/imágenes/fuentes]")
    assets = [
        ("/global-protect/portal/css/bootstrap.min.css", "css"),
        ("/global-protect/portal/css/login.css", "css"),
        ("/global-protect/portal/css/latofonts.css", "css"),
        ("/global-protect/portal/js/jquery.min.js", "javascript"),
        ("/global-protect/portal/images/logo-pan-48525a.svg", "svg"),
        ("/global-protect/portal/images/logo-pan-48525a.png", "image"),
        ("/global-protect/portal/images/favicon.ico", "icon"),
        ("/global-protect/portal/fonts/Lato-Regular.woff2", "font"),
        ("/global-protect/portal/images/bg.png", "image"),
    ]
    for path, pista in assets:
        r = get(path)
        nombre = path.split("/")[-1]
        if r.status_code != 200:
            fail(f"{nombre} HTTP 200", f"got {r.status_code}")
            continue
        ct = r.headers.get("Content-Type", "")
        if pista in ct or (pista == "font" and ct == "application/octet-stream"):
            ok(f"{nombre} 200 ({len(r.content):,} B)")
        else:
            fail(f"{nombre} Content-Type", ct or "ausente")


def test_prelogin():
    """Los endpoints que consulta el cliente GlobalProtect."""
    section("prelogin  [lo que pide el cliente GP]")
    for path in ("/ssl-vpn/prelogin.esp", "/global-protect/prelogin.esp"):
        r = get(path)
        if r.status_code != 200:
            fail(f"{path} 200", f"got {r.status_code}")
            continue
        if "<prelogin-response>" in r.text:
            ok(f"{path} 200 con <prelogin-response>")
        else:
            fail(f"{path} con <prelogin-response>", r.text[:80])
        if "application/xml" in r.headers.get("Content-Type", ""):
            ok(f"{path} Content-Type XML")
        else:
            fail(f"{path} Content-Type XML", r.headers.get("Content-Type", "?"))


def test_getsoftware():
    """La página de descarga del agente."""
    section("getsoftwarepage  [página del agente]")
    r = get("/global-protect/getsoftwarepage.esp")
    if r.status_code == 200 and "text/html" in r.headers.get("Content-Type", ""):
        ok("HTTP 200 HTML", f"{len(r.content):,} B")
    else:
        fail("HTTP 200 HTML", f"{r.status_code} {r.headers.get('Content-Type')}")


def test_logout_codes():
    """logout.esp pinta el mensaje del código que le llega."""
    section("logout.esp  [mensaje según ?code=N]")
    r = get("/global-protect/logout.esp?code=6")
    if r.status_code != 200:
        fail("HTTP 200", f"got {r.status_code}")
        return
    ok("HTTP 200")
    if "logout_text_array[ 6 ]" in r.text:
        ok("Indexa el mensaje 6 (sesión caducada)")
    else:
        fail("Indexa el mensaje 6", "el índice no se reescribió")
    r2 = get("/global-protect/logout.esp?code=0")
    if "logout_text_array[ 0 ]" in r2.text:
        ok("Indexa el mensaje 0 cuando el código es 0")
    else:
        fail("Indexa el mensaje 0", "el índice no se reescribió")
    if "Log In Again" in r.text:
        ok("Ofrece «Log In Again»")
    else:
        fail("Ofrece «Log In Again»")


def test_captura():
    """Un POST con credenciales se captura y repinta el error."""
    section("Captura de credenciales  [POST login.esp]")
    user = "gp.test@example.com"
    r = get("/global-protect/login.esp")
    token = re.search(r'name="csrf-token" value="([^"]+)"', r.text).group(1)
    r = post("/global-protect/login.esp", data={
        "prot": "https:", "server": "portal.example.com", "inputStr": "",
        "action": "getsoftware", "csrf-token": token,
        "user": user, "passwd": "GpPass2026!", "ok": "Log In",
    })
    if r.status_code == 200:
        ok("POST 200")
    else:
        fail("POST 200", f"got {r.status_code}")
    # El texto va en respMsg: la página hace `errMsg += "<li>" + respMsg` en la
    # rama de error, así que si estuviera en los dos saldría duplicado.
    if 'var respMsg = "Invalid username or password";' in r.text:
        ok("Repinta el formulario con el error")
    else:
        fail("Repinta el formulario con el error", r.text[:100])
    if 'var errMsg = "<li>' not in r.text:
        ok("Sin duplicar el mensaje (errMsg vacío, como el original)")
    else:
        fail("Sin duplicar el mensaje", "errMsg lleva texto y respMsg también")
    if f'value="{user}"' in r.text:
        ok("Conserva el usuario enviado")
    else:
        fail("Conserva el usuario enviado")
    time.sleep(0.15)
    ev = cred_in_log(user)
    if ev:
        ok("Credenciales en el log", f"user={ev['username']}")
        if ev.get("password") == "GpPass2026!":
            ok("Contraseña capturada", ev["password"])
        else:
            fail("Contraseña capturada", str(ev.get("password")))
    else:
        fail("Credenciales en el log", "no aparece el evento")


def test_post_sin_sesion():
    """Sin csrf-token el portal da la sesión por muerta (code=6)."""
    section("POST sin sesión  [→ logout.esp?code=6]")
    r = post("/global-protect/login.esp", data={"user": "x", "passwd": "y"})
    if "logout.esp?code=6" in r.text:
        ok("Responde con el salto a logout.esp?code=6")
    else:
        fail("Responde con el salto a logout.esp?code=6", r.text[:100])


def test_404():
    """El 404 del frontal, con y sin el relleno para navegadores."""
    section("404  [141 B con curl, 543 B con navegador]")
    for path in ("/nope", "/global-protect/nope"):
        # La sesión lleva UA de Chrome → el portal rellena la página.
        r = get(path)
        if r.status_code == 404 and len(r.content) == 543 and b"404 Not Found" in r.content:
            ok(f"GET {path} → 404 de 543 B (rellenado, como con un navegador)")
        else:
            fail(f"GET {path} → 404 de 543 B", f"{r.status_code} {len(r.content)} B")

    r = get("/nope", headers={"User-Agent": "curl/8.7.1"})
    if r.status_code == 404 and len(r.content) == 141:
        ok("GET /nope con UA de curl → 404 de 141 B (sin relleno)")
    else:
        fail("GET /nope con UA de curl → 404 de 141 B", f"{r.status_code} {len(r.content)} B")


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
        "/global-protect/login.esp",
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


def test_log():
    """Todo request queda en honeypot.log."""
    section("Log de peticiones")
    log_path = Path(__file__).parent / "honeypot.log"
    antes = log_path.stat().st_size if log_path.exists() else 0
    get("/global-protect/login.esp")
    time.sleep(0.1)
    despues = log_path.stat().st_size if log_path.exists() else 0
    if despues > antes:
        ok("El log crece con cada petición", f"+{despues - antes} B")
    else:
        fail("El log crece con cada petición")


# ─── Main ─────────────────────────────────────────────────────────────────────
def start_server(port):
    """
    Levanta la app con el MISMO servidor que producción (uvicorn + a2wsgi).

    Con el servidor de desarrollo de Flask el propio Werkzeug añade su cabecera
    `Server` y no se podría comprobar lo que de verdad importa: que el honeypot
    no la manda, como el portal real.
    """
    import logging
    logging.getLogger("honeypot").setLevel(logging.ERROR)
    log_path = Path(__file__).parent / "honeypot.log"
    log_path.unlink(missing_ok=True)

    import uvicorn
    config = uvicorn.Config(
        "asgi:app", host="127.0.0.1", port=port,
        log_level="error", access_log=False,
        server_header=False, date_header=False,
    )
    uvicorn.Server(config).run()


def main():
    global session, PORT
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    PORT = args.port

    threading.Thread(target=start_server, args=(PORT,), daemon=True).start()
    time.sleep(2.5)

    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )

    print(f"\n{Colors.BOLD}{'=' * 70}")
    print("  GlobalProtect Honeypot — E2E Test Suite")
    print(f"  Port: {PORT}")
    print(f"  Static cache: {honeypot_app.STATIC_DIR}")
    print(f"{'=' * 70}{Colors.RESET}")

    for suite in (test_headers, test_root_redirect, test_login_page,
                  test_token_rota, test_assets, test_prelogin,
                  test_getsoftware, test_logout_codes, test_captura,
                  test_post_sin_sesion, test_404, test_telegram_escape, test_log):
        try:
            suite()
        except Exception as e:
            fail(f"[EXCEPTION in {suite.__name__}]", str(e))

    passed = sum(1 for _, p, _ in RESULTS if p)
    total = len(RESULTS)
    failed = [(n, d) for n, p, d in RESULTS if not p]

    print(f"\n{Colors.BOLD}{'=' * 70}")
    color = Colors.GREEN if not failed else Colors.RED
    print(f"  {color}Resultado: {passed}/{total} tests pasados{Colors.RESET}{Colors.BOLD}")
    print(f"{'=' * 70}{Colors.RESET}")
    if failed:
        print(f"\n{Colors.RED}Failures:{Colors.RESET}")
        for name, detail in failed:
            print(f"  ✗ {name}  →  {detail}")

    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
