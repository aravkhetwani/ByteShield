# --- stage 1: build the React dashboard -------------------------------------------------------
FROM node:22-slim AS dashboard
WORKDIR /dashboard
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY dashboard/ ./
RUN npm run build

# --- stage 2: gateway + demo MCP servers --------------------------------------------------------
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 BYTESHIELD_DATA=/app/data BYTESHIELD_DEMO=1
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY byteshield ./byteshield
COPY demo_servers ./demo_servers
COPY demo ./demo
COPY config ./config
COPY --from=dashboard /dashboard/dist ./dashboard/dist
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health')"
CMD ["python", "-m", "byteshield", "--host", "0.0.0.0", "--port", "8080"]
