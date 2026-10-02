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

Las capturas en Vercel se avisan por Telegram: el disco allí es efímero. Ver las
variables `TELEGRAM_*` en el README de cada uno.

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
