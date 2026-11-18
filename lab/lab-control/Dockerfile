FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy lab-control source
COPY main.py .
# start.sh runs uvicorn on two ports:
# 9100 — lab control API (scope-excluded from scanner)
# 80   — IMDSv1 metadata simulator (169.254.169.100:80, internal_net only)
COPY start.sh .
RUN chmod +x start.sh

ENV TRUTH_DIR=/app/lab/truth
ENV PYTHONUNBUFFERED=1

EXPOSE 9100
EXPOSE 80

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9100/__lab/mode')" || exit 1

CMD ["/app/start.sh"]
