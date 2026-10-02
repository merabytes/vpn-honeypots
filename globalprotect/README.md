# Honeypot Palo Alto GlobalProtect

Copia estática de un portal GlobalProtect (PAN-OS) que se sirve tal cual y
guarda las credenciales que le llegan. No hace proxy contra el original: todo
sale de `static_cache/`, así que no hay tráfico hacia el sistema real.

El honeypot es agnóstico de marca: al capturar, el host original se sustituye
por el marcador `{{HOST}}` y en cada petición se reescribe al host por el que
entren. El mismo `static_cache/` sirve para cualquier dominio.

## Puesta en marcha

La primera vez crea `.venv/` e instala `requirements.txt`; después arranca
directo.

```bash
bash run.sh --dev     # uvicorn en :8444 con autoreload (desarrollo)
bash run.sh           # uvicorn en :443, 4 workers      (producción)
```

El puerto de desarrollo es 8444 (no 8443) para poder tener levantado a la vez el
honeypot de Citrix Gateway de al lado.

## Capturar otro portal

```bash
.venv/bin/python download.py --host portal.miempresa.com
```

Descarga la página de logon y todo lo que cuelga de ella —CSS, JS, fuentes,
imágenes, el 404 del frontal— más los endpoints que consulta el cliente
GlobalProtect (`/ssl-vpn/prelogin.esp`, `/global-protect/prelogin.esp`) y la
página de descarga del agente. Sólo hace GET/POST pasivos.

Ojo: los PAN-OS no negocian la renegociación segura de TLS (RFC 5746) y OpenSSL
moderno corta la conexión con `UNSAFE_LEGACY_RENEGOTIATION_DISABLED`. curl pasa
porque su OpenSSL lo permite; `download.py` activa `OP_LEGACY_SERVER_CONNECT`
para que Python también.

## Dónde quedan las capturas

| Fichero | Contenido |
| --- | --- |
| `honeypot.log` | Todos los eventos: cada request y cada captura |
| `creds.log` | Sólo los eventos `CREDENTIAL_CAPTURE` |

```json
{"ts": "2026-10-02T10:52:11Z", "event": "CREDENTIAL_CAPTURE",
 "path": "/global-protect/login.esp", "ip": "203.0.113.7",
 "username": "ana.lopez", "password": "…",
 "extra_fields": {"action": "getsoftware", "prot": "https:"},
 "geo": {"city": "Madrid"}}
```

## Variables de entorno

| Variable | Por defecto | Para qué |
| --- | --- | --- |
| `PORT` | `443` | Puerto de producción |
| `DEV_PORT` | `8444` | Puerto del modo dev |
| `WORKERS` | `4` | Workers de uvicorn |
| `TELEGRAM_BOT_TOKEN` | — | Token del bot (BotFather) para avisar de cada captura |
| `TELEGRAM_CHAT_ID` | — | Id del grupo destino (p. ej. `-1001234567890`) |
| `TELEGRAM_TOPIC_ID` | — | Id del topic, si el grupo es de tipo foro (`message_thread_id`) |
| `HONEYPOT_DATA_DIR` | la carpeta del proyecto | Dónde escribir `honeypot.log`/`creds.log` (en Vercel, `/tmp`) |
| `LOG_LEVEL` | `INFO` | Nivel de log de la aplicación |

Los nombres de Telegram son los de ShellGuard, y también se aceptan los cortos
`TG_TOKEN`, `TG_CHAT_ID` y `TG_TOPIC_ID`. El bot tiene que estar en el grupo. En
el README del repo está el paso a paso para sacar el id del grupo y el del topic
(`getUpdates` + `message_thread_id`) y para probarlo antes de fiarse.

El aviso se manda **en el momento**, no en segundo plano: en serverless un hilo
de fondo puede morir al terminar la respuesta y perder la captura.

La geolocalización (ip-api.com) va siempre activada, como en el de Citrix.

## Desplegar en Vercel

```bash
./deploy.sh              # producción
./deploy.sh --preview    # preview
```

Producción: <https://vpns-globalprotect-xavis-projects-d1fc3ed1.vercel.app/>

El proyecto de Vercel apunta al repo `vpn-honeypots` con esta carpeta como *Root
Directory* (un push a `main` despliega solo, en cuanto la GitHub App de Vercel
tenga acceso al repo); `deploy.sh` es la vía manual.

Vercel detecta el proyecto como Flask y mete **todo el directorio** dentro de la
función. Como aquí viven también `honeypot.log` y `creds.log` —con credenciales
de verdad— y el CLI deja un `.env.local` con un token, desplegar a pelo sería una
fuga esperando a pasar. Por eso `deploy.sh` monta un directorio temporal con la
lista blanca (`app.py`, `asgi.py`, `static_cache/`, `requirements.txt`) y
despliega desde ahí: lo que haya en la carpeta no importa.

Para configurar el aviso de Telegram en el despliegue:

```bash
vercel env add TELEGRAM_BOT_TOKEN production   # pega el token cuando lo pida
vercel env add TELEGRAM_CHAT_ID production
vercel env add TELEGRAM_TOPIC_ID production
./deploy.sh                                     # las env vars necesitan despliegue nuevo
```

Lo que cambia respecto a servirlo tú:

| | Servidor propio | Vercel |
| --- | --- | --- |
| Disco | `honeypot.log` y `creds.log` en la carpeta | efímero (`/tmp`); la captura vive en Telegram |
| Cabecera `Server` | ninguna, como el original | `Vercel`: la pone su borde y no se puede quitar |
| Dominio | el que apuntes | `*.vercel.app` o uno propio |

El proyecto tenía activada la autenticación de Vercel (protege los dominios
`*.vercel.app`); se ha desactivado para que sea alcanzable. Para volver a
protegerlo: *Settings → Deployment Protection* en el panel.

## Qué se replica

- `GET /` → 302 a `/global-protect/login.esp` con el salto por JavaScript y su
  cookie `SESSID`.
- La página de logon, con un `csrf-token` **nuevo en cada visita** (el real
  reparte uno distinto cada vez) y una `SESSID` nueva, igual que el original.
- Las cabeceras del portal: **sin `Server`** (lo esconde), con `Date`,
  `X-Frame-Options: DENY`, HSTS, `X-Content-Type-Options`, `X-XSS-Protection` y
  su CSP.
- El 404 del frontal: 141 B para clientes que no son navegador y 543 B
  rellenado con el comentario de «padding to disable MSIE and Chrome friendly
  error page» cuando el User-Agent lleva `Chrome/` o `MSIE `. La regla está
  medida contra el portal real (Firefox, Safari, Edge, Chromium, curl y
  python-requests no lo llevan).
- `logout.esp?code=N`: la página de sesión cerrada, con el mensaje que toca
  según el código (cadena de `logout_text_array[N]` del propio portal).
- `prelogin.esp` (en `/ssl-vpn/` y en `/global-protect/`): el XML que consulta
  el cliente GlobalProtect, con su fingerprint de versión.
- Un POST sin el `csrf-token` de la sesión recibe lo mismo que da el portal
  real: `<script>window.location="/global-protect/logout.esp?code=6";</script>`.

Lo que **no** se pudo verificar contra el original: el mensaje exacto que
devuelve el portal cuando la contraseña es incorrecta. No se han enviado
credenciales al sistema real, así que el honeypot repinta el formulario con
«Invalid username or password» (el mecanismo `errMsg`/`#dError` que trae la
propia página) y conserva el usuario. El resto del flujo sí está medido.

## Tests

```bash
.venv/bin/python test_e2e.py
```

49 comprobaciones: cabeceras, cadena de URLs, página de logon, rotación del
`csrf-token`, assets, prelogin, getsoftwarepage, códigos de logout, captura de
credenciales, el POST sin sesión y los dos tamaños del 404. Levanta la app con
uvicorn (el mismo servidor que producción), no con el de desarrollo de Flask.
