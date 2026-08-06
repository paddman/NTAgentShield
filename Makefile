.PHONY: install dev test lint serve replay docker agent

install:
	python -m pip install .

dev:
	python -m pip install -e '.[dev]'

test:
	pytest --cov=ntshield --cov-report=term-missing

lint:
	ruff check src tests

serve:
	ntshield serve --reload

replay:
	ntshield replay examples/zero_day_web_chain.jsonl

docker:
	docker compose up --build

agent:
	cd agent && go build -o ntshield-agent ./cmd/ntshield-agent
