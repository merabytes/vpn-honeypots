# Honeypot NetScaler / Citrix Gateway

Copia estática de un NetScaler Gateway (Citrix Gateway + Receiver for Web) que
se sirve tal cual y guarda las credenciales que le llegan. No hace proxy contra
el original: todo sale de `static_cache/`, así que no hay tráfico hacia el
sistema real ni depende de que esté levantado.

El honeypot es agnóstico de marca. Al capturar, el host original se sustituye
por el marcador `{{HOST}}`; en cada petición `app.py` lo reescribe al host por
el que estén entrando. El mismo `static_cache/` sirve para cualquier dominio.

## Puesta en marcha

La primera vez crea `.venv/` e instala `requirements.txt`; después arranca
directo.

```bash
bash run.sh --dev     # uvicorn en :8443 con autoreload (desarrollo)
bash run.sh           # uvicorn en :443, 4 workers      (producción)
```

`PORT` y `WORKERS` cambian el bind de producción (`443` y `4` por defecto).
En los dos modos la app WSGI se sirve con uvicorn a través del puente ASGI de
`asgi.py` y con `--no-server-header --no-date-header`: así las únicas cabeceras
`Server` y `Date` que salen son las de `app.py` («Apache», como el original) y
no aparece ni un `Server: uvicorn`.

## Capturar otro NetScaler

```bash
python3 download.py --host mi.empresa.com
```

Descarga la página de logon y todo lo que cuelga de ella —HTML, CSS, JS,
imágenes, fuentes y los endpoints XML/JSON que consulta el Receiver— y lo deja
en `static_cache/` con la misma estructura de rutas que el original. Sólo hace
GET/POST pasivos del mismo host; los recursos de terceros (reCAPTCHA, CDN) se
dejan apuntando fuera, como en el original.

## Dónde quedan las capturas

Ambos ficheros son JSON por línea:

| Fichero | Contenido |
| --- | --- |
| `honeypot.log` | Todos los eventos: cada request y cada captura |
| `creds.log` | Sólo los eventos `CREDENTIAL_CAPTURE` |

```json
{"ts": "2026-10-02T10:08:01Z", "event": "CREDENTIAL_CAPTURE",
 "path": "/nf/auth/doAuthentication.do", "ip": "203.0.113.7",
 "username": "ana.lopez", "password": "…",
 "extra_fields": {"savecredentials": "false"}, "geo": {"city": "Madrid"}}
```

`tail_log.py` los muestra en vivo ya formateados.

## Variables de entorno

| Variable | Por defecto | Para qué |
| --- | --- | --- |
| `PORT` | `443` | Puerto de producción |
| `WORKERS` | `4` | Workers de uvicorn |
| `GEOIP_ENABLED` | `1` | Geolocalizar la IP de cada captura (ip-api.com) |
| `TELEGRAM_BOT_TOKEN` | — | Token del bot (BotFather) para avisar de cada captura |
| `TELEGRAM_CHAT_ID` | — | Id del grupo destino (p. ej. `-1001234567890`) |
| `TELEGRAM_TOPIC_ID` | — | Id del topic, si el grupo es de tipo foro (`message_thread_id`) |
| `HONEYPOT_DATA_DIR` | la carpeta del proyecto | Dónde escribir `honeypot.log`/`creds.log` (en Vercel, `/tmp`) |
| `LOG_LEVEL` | `INFO` | Nivel de log de la aplicación |

Los nombres de Telegram son los de ShellGuard, y también se aceptan los cortos
`TG_TOKEN`, `TG_CHAT_ID` y `TG_TOPIC_ID`. El bot tiene que estar en el grupo; el
id del topic es el número que aparece en el enlace de un mensaje de ese topic
(`t.me/c/<grupo>/<topic>`).

El aviso se manda **en el momento**, no en segundo plano: en serverless un hilo
de fondo puede morir al terminar la respuesta y perder la captura.

## Desplegar en Vercel

```bash
./deploy.sh              # producción
./deploy.sh --preview    # preview
```

Producción: <https://vpns-citrix-gateway-xavis-projects-d1fc3ed1.vercel.app/>

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
| Cabecera `Server` | `Apache`, como el original | `Vercel`: la pone su borde y no se puede quitar |
| Dominio | el que apuntes | `*.vercel.app` o uno propio |

El proyecto tenía activada la autenticación de Vercel (protege los dominios
`*.vercel.app`); se ha desactivado para que sea alcanzable. Para volver a
protegerlo: *Settings → Deployment Protection* en el panel.

## Qué se replica

- La cadena de URLs del original: `/` → `/vpn/index.html` →
  `/logon/LogonPoint/tmindex.html`, con los mismos 302.
- El flujo de autenticación del Receiver: `Resources/List` responde
  `{"unauthorized": true}` con el challenge real (`location="/cgi/GetAuthMethods"`),
  `GetAuthMethods` declara `ExplicitForms` y `getAuthenticationRequirements.do`
  devuelve el formulario nFactor capturado.
- Las cabeceras reales de cada recurso (CSP, `X-Citrix-Application`, etc.), que
  se graban en `static_cache/_meta.json` y se reenvían.
- El 404 del Apache que hay delante del NetScaler.
- Los fingerprints: `/vpn/pluginlist.xml` y el emisor OIDC de
  `/oauth/idp/.well-known/openid-configuration`.

Lo que **no** se replica: la página posterior al login (el store de
aplicaciones). Un login correcto devuelve el formulario con el error
«Incorrect user name or password.», igual que el original ante credenciales
inválidas.

## Tests

```bash
.venv/bin/python test_e2e.py
```

Cubre fingerprint, nFactor, challenge, captura de credenciales y todos los
assets de la página.

## Ficheros

| Ruta | Qué es |
| --- | --- |
| `app.py` | El servidor: sirve `static_cache/` replicando el original y captura |
| `asgi.py` | Puente WSGI → ASGI para servir `app.py` con uvicorn |
| `download.py` | La captura de un NetScaler nuevo |
| `static_cache/` | La copia (host anonimizado como `{{HOST}}`) |
| `run.sh` | Arranque con bootstrap del entorno |
| `test_e2e.py` | Suite end-to-end |
| `tail_log.py` | Visor de capturas en vivo |
