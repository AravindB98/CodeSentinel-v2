.PHONY: help install install-all ingest benchmark benchmark-paired benchmark-multi benchmark-baseline semgrep-compare ui api scan test lint format typecheck synth sbom docker docker-run clean

PY := python3

help:
	@echo "CodeSentinel — available targets"
	@echo ""
	@echo "  make install        Install core (offline-capable) package"
	@echo "  make install-all    Install with all extras (llm, rag, api, graph, ui, dev)"
	@echo "  make ingest         Build the RAG knowledge base"
	@echo "  make scan PATH=.    Scan a path with the CLI (SARIF to stdout)"
	@echo "  make api            Run the REST API service"
	@echo "  make ui             Launch the Streamlit UI"
	@echo "  make benchmark      Run full eval (baseline + multi-agent)"
	@echo "  make test           Run the test suite"
	@echo "  make lint           Ruff lint"
	@echo "  make format         Ruff format"
	@echo "  make typecheck      mypy type check"
	@echo "  make sbom           Generate CycloneDX SBOM"
	@echo "  make docker         Build the container image"
	@echo "  make clean          Remove build artifacts"
	@echo ""

install:
	$(PY) -m pip install -e .

install-all:
	$(PY) -m pip install -e ".[all,dev]"

ingest:
	$(PY) -m codesentinel.rag.ingest

scan:
	$(PY) -m codesentinel.cli scan $(or $(PATH_),.) --format sarif

api:
	$(PY) -m codesentinel.cli serve

ui:
	streamlit run app/streamlit_app.py

benchmark:
	$(PY) -m eval.run_benchmark --mode both

benchmark-paired:
	$(PY) -m eval.run_benchmark --mode both --suite eval/datasets/paired_suite.json

benchmark-multi:
	$(PY) -m eval.run_benchmark --mode multi

benchmark-baseline:
	$(PY) -m eval.run_benchmark --mode baseline

semgrep-compare:
	@echo "Runs Semgrep + CodeSentinel on the same files and produces an adjudication worksheet."
	$(PY) -m eval.semgrep_compare --files $(FILES) --out eval/results/semgrep_comparison/

test:
	CODESENTINEL_MOCK_LLM=1 $(PY) -m pytest tests/ -v

lint:
	$(PY) -m ruff check codesentinel/ tests/

format:
	$(PY) -m ruff format codesentinel/ tests/

typecheck:
	$(PY) -m mypy codesentinel/

synth:
	$(PY) -m codesentinel.synth.generate --count 20 --out eval/datasets/synthetic_suite.json
	$(PY) -m codesentinel.synth.verify eval/datasets/synthetic_suite.json

sbom:
	$(PY) -m codesentinel.cli sbom --output sbom.cdx.json

docker:
	docker build -t codesentinel:$(shell $(PY) -c "import codesentinel; print(codesentinel.__version__)" 2>/dev/null || echo latest) .

docker-run:
	docker run --rm -p 8080:8080 -e ANTHROPIC_API_KEY codesentinel:latest

clean:
	rm -rf codesentinel/rag/chroma_store codesentinel/rag/tfidf_index.pkl codesentinel/rag/tfidf_index.json
	rm -rf eval/results/2026* build dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
