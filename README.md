# cgv
## Run
docker compose up -d --build
./api/smoke.sh
## Dev
make alembic-rev m="change"
make alembic-up
