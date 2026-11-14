FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin magpie
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./
USER magpie
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
