.PHONY: help install lab-up lab-down run seed reset demo clean

PY ?= python3
VENV := backend/.venv
BIN := $(VENV)/bin

help:
	@echo "ShadowTrace backend targets:"
	@echo "  make install     Create venv + install backend deps"
	@echo "  make lab-up      Start the 4-container demo lab"
	@echo "  make lab-down    Stop + remove the lab"
	@echo "  make run         Start the FastAPI server on :8000"
	@echo "  make seed        Seed an offline demo scan into the DB"
	@echo "  make reset       Wipe shadowtrace.db"
	@echo "  make demo        reset + seed + run (offline demo mode)"
	@echo "  make clean       Remove venv + pycache"

install:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r backend/requirements.txt

lab-up:
	cd lab && docker compose up -d

lab-down:
	cd lab && docker compose down -v

run:
	$(BIN)/uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload

seed:
	$(BIN)/python -m backend.scripts.seed_demo

reset:
	rm -f backend/shadowtrace.db

demo: reset seed run

clean:
	rm -rf $(VENV) backend/**/__pycache__ backend/__pycache__
