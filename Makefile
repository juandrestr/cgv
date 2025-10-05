SHELL := /bin/bash

.PHONY: up down rebuild logs ps psql redis-shell api-shell tail

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
