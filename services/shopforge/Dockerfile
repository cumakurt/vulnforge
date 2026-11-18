FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY main.py catalog.json ./

ENV PYTHONUNBUFFERED=1
ENV PORT=3100

EXPOSE 3100

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3100/health')" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3100"]
