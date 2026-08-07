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
	# Continue generating the report even if policy evaluation fails.
	-$(MAKE) scan REPORT=$(REPORT)
	$(MAKE) report
