# En Windows sin make: powershell -File scripts/tasks.ps1 <tarea>
COMPOSE = docker compose -f docker-compose.yml -f docker-compose.experiment.yml
PYTHON ?= python

.PHONY: env up down reset health logs lint test test-unit experiment report

env:
	@test -f .env || cp .env.example .env

up: env
	$(COMPOSE) up -d --build --wait

down:
	$(COMPOSE) down

reset:
	$(COMPOSE) down -v

health:
	$(PYTHON) scripts/check_health.py

logs:
	$(COMPOSE) logs -f --tail=100

lint:
	$(PYTHON) -m ruff check .

test-unit:
	$(PYTHON) -m pytest common/tests services -q

test:
	$(PYTHON) -m pytest -q

experiment:
	$(PYTHON) experiment/run.py

report:
	$(PYTHON) experiment/report.py
