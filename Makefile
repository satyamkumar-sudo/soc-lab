SHELL := /bin/bash

.PHONY: certs up down ps logs init airflow-shell api-shell clickhouse-shell grafana-reset
.PHONY: gke-auth aks-auth
.PHONY: up-gcp up-azure

certs:
	@bash ./scripts/gen_certs.sh

init: certs
	@mkdir -p data secrets
	@echo "Init complete. Put your GCP service account JSON at ./secrets/gcp-sa.json"

gke-auth:
	@bash ./scripts/gke_get_credentials.sh

aks-auth:
	@bash ./scripts/aks_get_credentials.sh

up:
	docker compose up -d --build --force-recreate

up-gcp:
	SOC_ENV_FILE=.env docker compose --env-file .env up -d --build --force-recreate

up-azure:
	SOC_ENV_FILE=.env.azure-dev docker compose --env-file .env.azure-dev up -d --build --force-recreate

down:
	docker compose down -v

ps:
	docker compose ps

logs:
	docker compose logs -f --tail=200

airflow-shell:
	docker compose exec airflow-webserver bash

api-shell:
	docker compose exec soc-api bash

clickhouse-shell:
	docker compose exec clickhouse clickhouse-client --user "$${CLICKHOUSE_USER}" --password "$${CLICKHOUSE_PASSWORD}" --database "$${CLICKHOUSE_DB}"

grafana-reset:
	docker compose stop grafana
	docker volume rm soc-lab_grafana_data || true
	docker compose up -d grafana

