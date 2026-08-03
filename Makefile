install:
	python3 -m pip install -r requirements.txt

test:
	pytest

scan-report:
	./scripts/summarize.py $(REPORT)
