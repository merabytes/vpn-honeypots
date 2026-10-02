"""
asgi.py — puente WSGI → ASGI para servir el honeypot con uvicorn.

La aplicación es Flask (WSGI) y uvicorn sólo habla ASGI, así que se envuelve con
`a2wsgi.WSGIMiddleware`: uvicorn atiende la conexión y el código WSGI corre en un
pool de hilos, que es justo lo que necesita un honeypot (GeoIP y notificaciones
bloqueantes).

El puente de asgiref (`asgiref.wsgi.WsgiToAsgi`) NO vale aquí: revienta la
segunda petición de cada conexión keep-alive con «CurrentThreadExecutor already
quit or is broken», que es exactamente lo que hace un navegador al pedir el HTML
y luego sus assets (comprobado con un socket crudo: 302 y después 500).

Se arranca con:
    uvicorn asgi:app --host 0.0.0.0 --port 443 --workers 4 \
        --no-server-header --no-date-header

Esos dos flags son la razón de usar uvicorn: gunicorn (desde la 26) mete
`server` en sus cabeceras hop-by-hop, descarta la que manda la aplicación y
escribe siempre «Server: gunicorn». Aquí las únicas `Server` y `Date` que salen
son las que pone app.py («Server: Apache», como el NetScaler real).
"""

from a2wsgi import WSGIMiddleware

from app import app as flask_app

# El puente pasa los nombres de cabecera a minúsculas al cruzar a ASGI
# («server», «x-frame-options») y h11 los escribe tal cual, así que sin esto el
# honeypot respondería en minúsculas donde el original responde «Server: Apache».
# HTTP no distingue mayúsculas, pero un clon que se precie no da ni esa pista.
_GRAFIA = {
    b"etag": b"ETag",
    b"www-authenticate": b"WWW-Authenticate",
    b"x-xss-protection": b"X-XSS-Protection",
    b"te": b"TE",
    b"dnt": b"DNT",
}


def _grafia(nombre: bytes) -> bytes:
    minuscula = nombre.lower()
    if minuscula in _GRAFIA:
        return _GRAFIA[minuscula]
    return b"-".join(parte.capitalize() for parte in minuscula.split(b"-"))


class CabecerasCanonicas:
    """Devuelve a cada cabecera su grafía convencional antes de salir."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def send_con_grafia(message):
            if message["type"] == "http.response.start":
                message["headers"] = [
                    (_grafia(nombre), valor) for nombre, valor in message["headers"]
                ]
            await send(message)

        await self.app(scope, receive, send_con_grafia)


app = CabecerasCanonicas(WSGIMiddleware(flask_app))
