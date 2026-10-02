# VPN honeypots

Clones 1:1 de portales VPN que se sirven estáticos y capturan las credenciales
que les llegan. Cada carpeta es autónoma: se puede copiar a un servidor y
levantar ahí sin dependencias del resto.

| Carpeta | Qué clona | Puerto dev | Tests |
| --- | --- | --- | --- |
| [`citrix-gateway/`](citrix-gateway/) | NetScaler Gateway / Citrix Gateway (Receiver for Web) | 8443 | 65 |
| [`globalprotect/`](globalprotect/) | Palo Alto GlobalProtect (portal PAN-OS) | 8444 | 49 |

## Desplegados en Vercel

| Honeypot | URL |
| --- | --- |
| Citrix Gateway | <https://vpns-citrix-gateway-xavis-projects-d1fc3ed1.vercel.app/> |
| GlobalProtect | <https://vpns-globalprotect-xavis-projects-d1fc3ed1.vercel.app/> |

Los dos proyectos de Vercel apuntan a este repo, cada uno con su carpeta como
*Root Directory* (`citrix-gateway` y `globalprotect`), así que **un push a
`main` despliega los dos**. Para que la conexión funcione, la GitHub App de
Vercel necesita acceso a este repositorio (GitHub → Settings → GitHub Apps →
Vercel → Repository access). El repo sólo contiene lo que debe viajar —los logs
de capturas están en el `.gitignore`—, que es lo que hace segura esa vía.

Cada carpeta trae además un `deploy.sh` para desplegar a mano. Ese sí monta un
directorio temporal con lista blanca, porque Vercel mete el directorio entero
dentro de la función y en una carpeta de trabajo local pueden estar
`honeypot.log`/`creds.log` (con credenciales de verdad) y el `.env.local` que
deja el CLI.

Las capturas en Vercel se avisan por Telegram, porque el disco allí es efímero:
debajo está el paso a paso para montar el bot, el grupo y el topic.

## Alertas de Telegram (bot, grupo y topic)

Cada credencial capturada sale en el momento hacia un grupo de Telegram y, si el
grupo es de tipo foro, hacia un topic concreto. Es la única vía de captura en
Vercel —allí el disco es efímero— y el aviso cómodo cuando lo sirves tú.

### 1. El bot

Habla con [@BotFather](https://t.me/BotFather), `/newbot`, y guarda el token que
te devuelve (`123456789:AA…`). Ese es el `TELEGRAM_BOT_TOKEN`.

### 2. El grupo (y el topic)

Crea el grupo, actívale los *Topics* si quieres separar el ruido de cada
honeypot, y **añade el bot al grupo**. Si es de tipo foro, crea el topic donde
quieras las alertas (por ejemplo `Credenciales`).

### 3. El id del grupo

Manda un mensaje en el grupo mencionando al bot (`@tu_bot`) para que Telegram le
entregue el update, y pregúntale a la API:

```bash
curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" \
  | jq '.result[].message.chat | {id, title, type}'
```

El `id` de un grupo es negativo (`-1001234567890`). Ese es el
`TELEGRAM_CHAT_ID`.

### 4. El id del topic

Con el topic ya creado, escribe **dentro del topic** mencionando al bot y vuelve
a mirar los updates:

```bash
curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" \
  | jq '.result[].message | select(.is_topic_message) | {message_thread_id, text}'
```

Ese `message_thread_id` es el `TELEGRAM_TOPIC_ID`. También es el último número
del enlace de un mensaje del topic: `t.me/c/<grupo>/<topic>`.

### 5. Probarlo antes de fiarse

```bash
curl -s -X POST "https://api.telegram.org/bot<TOKEN>/sendMessage" \
  -d chat_id=<CHAT_ID> -d message_thread_id=<TOPIC_ID> \
  -d text="prueba de alertas" | jq '{ok, description}'
```

Si devuelve `ok: true`, el honeypot también podrá.

### 6. Configurarlo

En un servidor, exporta las tres antes de arrancar:

```bash
export TELEGRAM_BOT_TOKEN=123456789:AA...
export TELEGRAM_CHAT_ID=-1001234567890
export TELEGRAM_TOPIC_ID=42
bash run.sh
```

En Vercel (y después redespliega: la función lee las variables al arrancar):

```bash
cd globalprotect        # y lo mismo en citrix-gateway
vercel env add TELEGRAM_BOT_TOKEN production
vercel env add TELEGRAM_CHAT_ID production
vercel env add TELEGRAM_TOPIC_ID production
./deploy.sh
```

También se aceptan los nombres cortos `TG_TOKEN`, `TG_CHAT_ID` y `TG_TOPIC_ID`.

### Qué llega

```
🎣 CREDENTIAL CAPTURED (GlobalProtect)
━━━━━━━━━━━━━━━━━━━━━━
👤 User: ana.lopez
🔑 Pass: …
🌐 IP: 203.0.113.7
🌍 Geo: Madrid, Spain (ES)
🏢 Org: Telefonica de Espana
🖥 UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) …
📍 Path: /global-protect/login.esp
🕐 TS: 2026-10-02 11:22:01 UTC
```

El envío es **síncrono** (con 5 s de timeout) a propósito: en serverless un hilo
en segundo plano puede morir al terminar la respuesta, y perder una captura es
lo peor que le puede pasar a un honeypot. Si Telegram lo rechaza —topic
equivocado, bot fuera del grupo, token caducado— el motivo queda en el log:
`[TG] Telegram rechazó el mensaje: <descripción>`.

## Cómo funciona cualquiera de ellos

1. `download.py` captura el portal real en `static_cache/` (HTML, CSS, JS,
   fuentes, imágenes y los endpoints que consulta el cliente). El host capturado
   se guarda como el marcador `{{HOST}}`, así que la copia no lleva la identidad
   de nadie.
2. `app.py` sirve esa copia replicando la estructura de URLs, los códigos de
   estado y las cabeceras del original, reescribe `{{HOST}}` al host de cada
   petición y guarda las credenciales.
3. `run.sh` monta el entorno (`venv` + `requirements.txt`) y arranca la app.

```bash
cd globalprotect
bash run.sh --dev      # levanta en :8444
bash run.sh            # producción en :443
```

## Convenciones

- **Nada de marca**: ni el código ni lo servido llevan el nombre del cliente del
  que se capturó. Lo único que lo menciona es `_meta.json`, que es el registro
  de la captura.
- **Sin proxy**: cero tráfico hacia el sistema original en tiempo de ejecución.
- **Mismo servidor en dev y en producción**: uvicorn con `--no-server-header` y
  `--no-date-header`, y el puente WSGI→ASGI de `a2wsgi` (el de asgiref revienta
  la segunda petición de cada conexión keep-alive). Las cabeceras `Server` y
  `Date` las pone `app.py` con la grafía del original.
- **Cada uno con su suite**: `.venv/bin/python test_e2e.py`.

## Añadir otro VPN

Copia la carpeta que más se parezca, cambia en `download.py` las semillas
(endpoints del portal) y en `app.py` la página de logon y las respuestas
particulares del fabricante. El resto (crawler, reescritura de host, servidor
estático, captura) es común.
