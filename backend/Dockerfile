FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt ./
# Keep the adapters and the required stdio gate, excluding unused proxy services.
RUN pip install --no-cache-dir --no-compile --require-hashes -r requirements.txt \
    && rm -rf /usr/local/lib/python3.13/site-packages/litellm/proxy/_experimental/out \
              /usr/local/lib/python3.13/site-packages/litellm/proxy/a2a \
              /usr/local/lib/python3.13/site-packages/litellm/proxy/agent_endpoints \
              /usr/local/lib/python3.13/site-packages/litellm/proxy/swagger \
              /usr/local/lib/python3.13/site-packages/litellm/proxy/_lazy_openapi_snapshot.json \
              /usr/local/lib/python3.13/site-packages/litellm/proxy/management_endpoints \
              /usr/local/lib/python3.13/site-packages/litellm/proxy/ui_crud_endpoints \
              /usr/local/lib/python3.13/site-packages/litellm/proxy/workflows \
              /usr/local/lib/python3.13/site-packages/litellm/a2a_protocol \
    && find /usr/local/lib/python3.13/site-packages/litellm/proxy/mcp_server -mindepth 1 -maxdepth 1 ! -name stdio_gate.py -exec rm -rf {} + \
    && rm -f /usr/local/lib/python3.13/site-packages/litellm/proxy/admin_mcp.py \
             /usr/local/lib/python3.13/site-packages/litellm/proxy/mcp_registry.json \
             /usr/local/lib/python3.13/site-packages/litellm/proxy/mcp_tools.py
RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin magpie
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./
USER magpie
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
