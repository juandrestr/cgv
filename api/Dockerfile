FROM python:3.11-slim
WORKDIR /app

# add curl for container healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENV PYTHONUNBUFFERED=1

# build-time metadata (passed via --build-arg)
ARG GIT_COMMIT=unknown
ARG APP_VERSION=dev
ENV GIT_COMMIT=$GIT_COMMIT
ENV APP_VERSION=$APP_VERSION

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
