#!/usr/bin/env bash
# deploy.sh — Despliega este honeypot en Vercel.
#
# Por qué no se despliega “a pelo” desde esta carpeta: Vercel detecta el
# proyecto como Flask y mete TODO el directorio dentro de la función. Aquí viven
# también honeypot.log y creds.log —con credenciales de verdad— y el CLI deja un
# .env.local con un token; subirlos sería una fuga esperando a pasar. Este
# script monta un directorio temporal con la lista blanca de lo que debe viajar
# y despliega desde ahí, así que lo que hay en la carpeta no importa.
#
# Uso:
#   ./deploy.sh              # producción
#   ./deploy.sh --preview    # preview (URL de prueba, sin tocar producción)
#
# Necesita el CLI de Vercel autenticado (`vercel login`).

set -euo pipefail
cd "$(dirname "$0")"

PROYECTO="${VERCEL_PROJECT:-vpns-globalprotect}"
SCOPE="${VERCEL_SCOPE:-xavis-projects-d1fc3ed1}"

if [ "${1:-}" = "--preview" ]; then
    TARGET="preview"
    DEPLOY_FLAGS=""
else
    TARGET="production"
    DEPLOY_FLAGS="--prod"
fi

if ! command -v vercel >/dev/null 2>&1; then
    echo "ERROR: no encuentro el CLI de vercel. Instálalo con: npm i -g vercel" >&2
    exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# El proyecto tiene esta carpeta como Root Directory (para que el repo con los
# dos honeypots despliegue cada uno por su lado desde git), y Vercel aplica ese
# ajuste también en los despliegues del CLI: el staging tiene que replicar la
# carpeta o el builder busca el código donde no está ("No Flask entrypoint
# found"). Así que se stagea dentro de su carpeta, como en el repo.
CARPETA="$(basename "$PWD")"
mkdir -p "$STAGE/$CARPETA"

# Lista blanca: sólo esto viaja al despliegue.
cp -R app.py asgi.py static_cache requirements.txt .python-version "$STAGE/$CARPETA/"
mkdir -p "$STAGE/.vercel"
if [ -f .vercel/project.json ]; then
    cp .vercel/project.json "$STAGE/.vercel/"
fi

cd "$STAGE"
if [ ! -f .vercel/project.json ]; then
    vercel link --yes --project "$PROYECTO" --scope "$SCOPE"
fi

# Refrescar los ajustes del proyecto: los locales pueden estar viejos (por
# ejemplo sin el Root Directory) y el build se comportaría distinto.
echo "[VERCEL] Bajando ajustes del proyecto ($TARGET)..."
vercel pull --yes --environment "$TARGET" >/dev/null

echo "[VERCEL] Construyendo ($TARGET) desde $STAGE..."
vercel build --yes --target "$TARGET"

echo "[VERCEL] Desplegando..."
vercel deploy --prebuilt --yes $DEPLOY_FLAGS
