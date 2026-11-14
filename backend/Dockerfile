FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt ./
# The gateway uses LiteLLM adapters, not LiteLLM's bundled proxy web console.
RUN pip install --no-cache-dir --require-hashes -r requirements.txt \
    && rm -rf /usr/local/lib/python3.13/site-packages/litellm/proxy/_experimental/out
RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin magpie
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./
USER magpie
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
