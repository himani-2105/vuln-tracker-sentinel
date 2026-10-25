FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV DB_PATH=/data/tracker.db VULNTRACK_ENV=production PYTHONUNBUFFERED=1
RUN useradd -r -u 10001 app && mkdir -p /data && chown -R app /data /app
USER app
EXPOSE 8000
# SECRET_KEY must be supplied at runtime. The app refuses to start in production without it.
CMD ["sh","-c","gunicorn -w 2 --timeout 60 -b 0.0.0.0:${PORT:-8000} app:app"]
