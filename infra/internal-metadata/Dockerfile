FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.111.0 uvicorn==0.29.0
COPY main.py .
ENV PYTHONUNBUFFERED=1
EXPOSE 80
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:80/health')" || exit 1
CMD ["python3", "main.py"]
