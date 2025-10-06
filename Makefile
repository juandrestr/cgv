.PHONY: smoke up logs

smoke:
	./smoke_test_m1_m5.sh

up:
	docker compose up -d --force-recreate api

logs:
	docker compose logs --tail=200 api
