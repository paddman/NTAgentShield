.PHONY: install dev test lint serve replay docker agent agent-test agent-race agent-fmt test-all

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
	cd agent && go build ./cmd/ntagentshield-agent ./cmd/ntagentshieldctl

agent-test:
	cd agent && go test ./...

agent-race:
	cd agent && go test -race ./...

agent-fmt:
	@files="$$(cd agent && gofmt -l .)"; \
	if [ -n "$$files" ]; then echo "Go files require formatting:"; echo "$$files"; exit 1; fi

test-all: lint test agent-fmt agent-test agent-race agent
