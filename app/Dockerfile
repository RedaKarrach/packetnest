FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin packetnest

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN chmod +x /app/entrypoint.sh \
    && mkdir -p /app/media /app/staticfiles \
    && chown -R packetnest:packetnest /app/media /app/staticfiles

USER packetnest

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
