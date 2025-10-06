FROM python:3.11-slim

WORKDIR /app

# ---- version/commit injection ----
ARG GIT_COMMIT=unknown
ARG APP_VERSION=dev
ENV GIT_COMMIT=${GIT_COMMIT} APP_VERSION=${APP_VERSION}

# deps
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# app
COPY . .
ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
