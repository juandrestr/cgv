.PHONY: smoke up logs

smoke:
	./smoke_test_m1_m5.sh
	./smoke_test_m6.sh
	./smoke_test_m6_logout_all.sh

up:
	docker compose up -d --force-recreate api
	for i in $$(seq 1 30); do \
	  curl -fsS http://127.0.0.1:8080/healthz >/dev/null && echo "healthz: OK" && break; \
	  sleep 1; \
	  if [ $$i -eq 30 ]; then echo "healthz: TIMEOUT"; exit 1; fi; \
	done

logs:
	docker compose logs --tail=200 api
