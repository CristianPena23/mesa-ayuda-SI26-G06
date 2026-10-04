# Parte 6 - Dockerfile endurecido (SI26-G06)
# H8: imagen "slim" -> menos paquetes, menos CVE, menos superficie de ataque.
FROM python:3.12-slim

# Python no escribe .pyc y muestra los logs al instante.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Primero solo las dependencias (mejor cache) y sin guardar la cache de pip.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# H6: solo se copia el codigo de la app (el .dockerignore excluye .env, .git, etc.).
COPY app ./app
# Los archivos quedan de root y solo de LECTURA para appuser: la app puede leer su
# codigo pero no modificarlo. chmod corrige permisos restrictivos del origen (700).
RUN chmod -R a+rX,go-w /app/app

# H5: usuario SIN privilegios. Si alguien explota la API, no es root en el contenedor.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/logs && chown appuser:appuser /app/logs
USER appuser

# H27: el puerto documentado coincide con el real del grupo.
EXPOSE 8106

# Comprueba que la API responde (Docker marca el contenedor "unhealthy" si no).
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.getenv('APP_PORT','8106'), timeout=3)" || exit 1

# H7: sin --reload (modo desarrollo). exec reemplaza al shell para que uvicorn
# reciba directamente las senales de parada de Docker.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${APP_PORT:-8106}"]
