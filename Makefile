SHELL := /bin/bash

.PHONY: up down rebuild logs ps psql redis-shell api-shell tail alembic-rev alembic-up

up:
	 docker compose up -d

down:
	 docker compose down

rebuild:
	 docker compose build api && docker compose up -d

logs:
	 docker compose logs -f api

ps:
	 docker compose ps

psql:
	 docker compose exec -it db psql -U cgv -d cgv

redis-shell:
	 docker compose exec -it redis redis-cli

api-shell:
	 docker compose exec -it api /bin/bash

tail:
	 curl -s http://127.0.0.1:8080/ready && echo
	 curl -s http://127.0.0.1:8080/version && echo
	 curl -s http://127.0.0.1:8080/metrics | head -n 12



alembic-rev:
	 docker run --rm --network cgv_default \
	   -e DATABASE_URL="postgresql+psycopg://cgv:cgv@db:5432/cgv" \
	   -v $(PWD)/api:/app -w /app cgv-api alembic revision --autogenerate -m "$(m)"

alembic-up:
	 docker run --rm --network cgv_default \
	   -e DATABASE_URL="postgresql+psycopg://cgv:cgv@db:5432/cgv" \
	   -v $(PWD)/api:/app -w /app cgv-api alembic upgrade head
