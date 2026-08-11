IMAGE ?= pywinrm-ansible:dev
REPORT_DIR ?= reports
LATEST_DIR ?= $(REPORT_DIR)/latest
REPORT ?= $(LATEST_DIR)/report.json
SUMMARY ?= $(LATEST_DIR)/summary.json
HTML ?= $(LATEST_DIR)/report.html

install:
	python3 -m pip install -r requirements.txt

test:
	pytest

scan:
	@mkdir -p "$(LATEST_DIR)"
	@./scripts/scan.sh "$(IMAGE)"
	@LATEST_SCAN=$$(find "$(REPORT_DIR)" -maxdepth 1 -type d -name '20*' | sort | tail -1); \
	if [ -z "$$LATEST_SCAN" ] || [ ! -f "$$LATEST_SCAN/report.json" ]; then \
		echo "ERROR: No scan report found."; \
		exit 1; \
	fi; \
	cp "$$LATEST_SCAN/report.json" "$(REPORT)"

summarize:
	@./scripts/summarize.py "$(REPORT)" > "$(SUMMARY)"

report:
	@./scripts/report.py "$(SUMMARY)" "$(HTML)" "$(IMAGE)"

security-report:
	@$(MAKE) scan IMAGE="$(IMAGE)"
	@-$(MAKE) summarize REPORT="$(REPORT)"
	@$(MAKE) report IMAGE="$(IMAGE)"
