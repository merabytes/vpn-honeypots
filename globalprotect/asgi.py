"""
asgi.py — puente WSGI → ASGI para servir el honeypot con uvicorn.

La aplicación es Flask (WSGI) y uvicorn sólo habla ASGI, así que se envuelve con
`a2wsgi.WSGIMiddleware`: uvicorn atiende la conexión y el código WSGI corre en un
pool de hilos, que es lo que necesita un honeypot (GeoIP y notificaciones
bloqueantes).

El puente de asgiref (`asgiref.wsgi.WsgiToAsgi`) NO vale aquí: revienta la
segunda petición de cada conexión keep-alive con «CurrentThreadExecutor already
quit or is broken», que es justo lo que hace un navegador al pedir el HTML y
luego sus assets.

Se arranca con:
    uvicorn asgi:app --host 0.0.0.0 --port 443 --workers 4 \
        --no-server-header --no-date-header

Los dos flags importan: el portal PAN-OS no manda cabecera `Server` (la esconde)
y sí manda `Date`. Aquí las pone app.py, así que el servidor no debe añadir las
suyas.
"""

from a2wsgi import WSGIMiddleware

from app import app as flask_app

# El puente pasa los nombres de cabecera a minúsculas al cruzar a ASGI
# («x-frame-options»), y h11 los escribe tal cual. El portal real las manda
# capitalizadas, así que se les devuelve su grafía antes de salir.
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
