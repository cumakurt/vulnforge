FROM python:3.12-slim

WORKDIR /app
COPY main.py .

ENV PYTHONUNBUFFERED=1
ENV PORT=8888
EXPOSE 8888

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8888/health')" || exit 1

CMD ["python3", "main.py"]
