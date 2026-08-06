.PHONY: install test lint run replay

install:
	python -m pip install -e '.[dev]'

test:
	pytest

lint:
	ruff check src tests

run:
	uvicorn ntshield.api:app --host 0.0.0.0 --port 8080 --reload

replay:
	ntshield-replay samples/webshell_chain.jsonl
