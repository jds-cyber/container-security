IMAGE ?= pywinrm-ansible:dev
REPORT_DIR ?= reports
LATEST_DIR ?= $(REPORT_DIR)/latest
SBOM_DIR ?= sbom
LATEST_SBOM_DIR ?= $(SBOM_DIR)/latest
SBOM ?= $(LATEST_SBOM_DIR)/sbom.json
REPORT ?= $(LATEST_DIR)/report.json
SUMMARY ?= $(LATEST_DIR)/summary.json
HTML ?= $(LATEST_DIR)/report.html
PYTHON ?= python3

install:
	python3 -m pip install -r requirements.txt

test:
	pytest

scan:
	@mkdir -p "$(LATEST_DIR)" "$(LATEST_SBOM_DIR)"
	@./scripts/scan.sh "$(IMAGE)"
	@LATEST_SCAN=$$(find "$(REPORT_DIR)" -maxdepth 1 -type d -name '20*' | sort | tail -1); \
	if [ -z "$$LATEST_SCAN" ] || [ ! -f "$$LATEST_SCAN/report.json" ]; then \
		echo "ERROR: No scan report found."; \
		exit 1; \
	fi; \
	if [ ! -f "$(SBOM_DIR)/$$(basename "$$LATEST_SCAN")/sbom.json" ]; then \
		echo "ERROR: No SBOM found for latest scan."; \
		exit 1; \
	fi; \
	cp "$$LATEST_SCAN/report.json" "$(REPORT)"; \
	cp "$(SBOM_DIR)/$$(basename "$$LATEST_SCAN")/sbom.json" "$(SBOM)"

summarize:
	@$(PYTHON) ./scripts/summarize.py \
		"$(REPORT)" \
		--scanner grype \
		--policy config/security_policy.yml \
		--osv \
		--epss \
		--sbom "$(SBOM)" \
		> "$(SUMMARY)"

report:
	@$(PYTHON) ./scripts/report.py "$(SUMMARY)" "$(HTML)" "$(IMAGE)"

security-report:
	@$(MAKE) scan IMAGE="$(IMAGE)"
	@set +e; \
	$(MAKE) summarize REPORT="$(REPORT)"; \
	SUMMARY_EXIT=$$?; \
	$(MAKE) report IMAGE="$(IMAGE)"; \
	REPORT_EXIT=$$?; \
	if [ $$REPORT_EXIT -ne 0 ]; then \
		exit $$REPORT_EXIT; \
	fi; \
	exit $$SUMMARY_EXIT
