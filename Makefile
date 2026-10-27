PY ?= python
DBT = dbt build --project-dir dbt_project --profiles-dir dbt_project

.PHONY: install generate normalize dbt demo test lint clean

install:
	pip install -e ".[dev]"

generate:
	$(PY) -m stl.cli generate

normalize:
	$(PY) -m stl.cli normalize

dbt:
	$(DBT)

# Full end-to-end run: synthetic events -> quality gate -> Parquet -> dbt models and tests
demo: generate normalize dbt
	@$(PY) -c "import duckdb; con = duckdb.connect('data/warehouse.duckdb', read_only=True); [print(r) for r in con.execute('select technique_id, detection_name, alerts_fired, coverage_status from detection_coverage').fetchall()]"

test:
	$(PY) -m pytest -q

lint:
	ruff check src tests dags

clean:
	rm -rf data/raw data/lakehouse data/quarantine data/quality_report.json data/warehouse.duckdb \
	       dbt_project/target dbt_project/logs dbt_project/dbt_packages logs
