test:
	python3 -m pytest -q

demo:
	./scripts/demo.sh

lint:
	ruff check boundary_audit tests

