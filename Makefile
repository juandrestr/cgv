.PHONY: build up info

# Always stamp the image with commit/tag
build:
	docker compose build \
	  --build-arg GIT_COMMIT=$$(git rev-parse --short HEAD) \
	  --build-arg APP_VERSION=$$(git describe --tags --always)

up: build
	docker compose up -d

# Quick info: show what's running & the stamped vars inside the api container
info:
	docker compose ps
	docker compose exec -T api /bin/sh -lc 'printf "GIT_COMMIT=%s APP_VERSION=%s\n" "$$GIT_COMMIT" "$$APP_VERSION"'
	curl -s http://localhost:8080/version || true && echo
