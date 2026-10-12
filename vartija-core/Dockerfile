FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

COPY pyproject.toml ./
COPY vartija_core ./vartija_core
RUN pip install --no-cache-dir ".[postgres]" uvicorn

COPY config ./config
COPY corpus ./corpus
COPY seed ./seed

RUN useradd --create-home vartija
USER vartija
EXPOSE 8001
CMD ["uvicorn", "vartija_core.api:app", "--host", "0.0.0.0", "--port", "8001"]
