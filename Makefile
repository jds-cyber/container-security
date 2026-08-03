REPORT ?= reports/latest/report.json

install:
	python3 -m pip install -r requirements.txt

test:
	pytest

scan:
	./scripts/summarize.py $(REPORT) > reports/latest/summary.json

report:
	./scripts/report.py reports/latest/summary.json reports/latest/report.html

security-report:
	-$(MAKE) scan || true
	$(MAKE) report
