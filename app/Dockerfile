# Slim image: minder pakketten betekent minder kwetsbaarheden om te patchen.
# 3.13 en niet 3.14, zodat pip overal kant-en-klare wheels vindt en er geen
# compiler in de image hoeft.
FROM python:3.13-slim

# Geen .pyc-bestanden en ongebufferde output, zodat logs direct zichtbaar zijn.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Eerst alleen requirements kopiëren: zolang dat bestand niet wijzigt
# hergebruikt Docker deze laag en hoeft pip niet opnieuw te draaien.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root draaien. Dit is de belangrijkste hardening-stap van deze image:
# een kwetsbaarheid in de applicatie levert dan geen root in de container op.
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

# Gunicorn, niet de ingebouwde Flask-server: die is expliciet niet bedoeld
# voor productie. Lokaal overschrijft compose.yaml dit commando met de
# dev-server, zodat je wel live reload hebt tijdens het bouwen.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]

# Nog te doen (hoort bij BoK secure configuration / image hardening):
# - Base image pinnen op een digest in plaats van een tag, zodat je exact
#   weet welke image je bouwt.
# - Multi-stage build als er ooit build-dependencies bijkomen.
# - Trivy op deze image in de pipeline.
