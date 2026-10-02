#!/usr/bin/env bash
# run.sh — Arranque del honeypot de NetScaler / Citrix Gateway.
#
# Uso:
#   bash run.sh          # producción (uvicorn, :443)
#   bash run.sh --dev    # desarrollo (Flask, :8443)
#
# La primera vez crea .venv/ e instala requirements.txt; después es inmediato.
# Compatible con el bash 3.2 que trae macOS.

set -euo pipefail
cd "$(dirname "$0")"

# ── Configuración ─────────────────────────────────────────────────────────────
PORT=${PORT:-443}
WORKERS=${WORKERS:-4}
BIND="0.0.0.0:${PORT}"
VENV=".venv"
PY_MIN="3.9"

# Notificaciones Telegram (opcional)
# export TG_TOKEN="1234567890:AAxxxx..."
# export TG_CHAT_ID="322767963"

# Geolocalización IP (por defecto activada)
export GEOIP_ENABLED=${GEOIP_ENABLED:-1}

# ── Entorno Python ────────────────────────────────────────────────────────────
python_suficiente() {
    "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null
}

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: no encuentro python3 en el PATH. Instala Python >= ${PY_MIN} y vuelve a intentarlo." >&2
    exit 1
fi

if ! python_suficiente python3; then
    echo "ERROR: python3 es $(python3 -V 2>&1) y hace falta >= ${PY_MIN}." >&2
    exit 1
fi

if [ ! -x "${VENV}/bin/python" ]; then
    echo "[ENV] Creando ${VENV}/ con $(python3 -V 2>&1)..."
    python3 -m venv "${VENV}"
fi

# El venv puede existir a medias (copiado sin las librerías, pip interrumpido):
# en ese caso se reinstala lo que falte.
if ! "${VENV}/bin/python" -c 'import flask, uvicorn, a2wsgi' >/dev/null 2>&1; then
    echo "[ENV] Instalando dependencias de requirements.txt..."
    "${VENV}/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
    if ! "${VENV}/bin/python" -m pip install --quiet -r requirements.txt; then
        echo "ERROR: no se pudieron instalar las dependencias (¿hay red?)." >&2
        exit 1
    fi
fi

# ── Dev mode ──────────────────────────────────────────────────────────────────
# Mismo servidor que en producción (así dev y prod no se comportan distinto y no
# aparece la cabecera «Server: Werkzeug»), con autoreload y un solo worker.
if [ "${1:-}" = "--dev" ]; then
    echo "[DEV] Arrancando uvicorn en :8443 (autoreload)..."
    export PORT=8443
    exec "${VENV}/bin/uvicorn" \
        asgi:app \
        --host 0.0.0.0 \
        --port 8443 \
        --reload \
        --no-server-header \
        --no-date-header \
        --timeout-keep-alive 5 \
        --log-level info
fi

# ── Producción (uvicorn) ──────────────────────────────────────────────────────
echo "[PROD] Arrancando uvicorn en ${BIND} (${WORKERS} workers)..."

# --no-server-header/--no-date-header: uvicorn escribe las suyas propias y el
# honeypot se delataría con «Server: uvicorn». Las dos las pone app.py, con la
# grafía del Apache del original («Server: Apache», «Date: …»).
exec "${VENV}/bin/uvicorn" \
    asgi:app \
    --host 0.0.0.0 \
    --port "${PORT}" \
    --workers "${WORKERS}" \
    --no-server-header \
    --no-date-header \
    --timeout-keep-alive 5 \
    --access-log \
    --log-level warning \
