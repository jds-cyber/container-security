# Container Security Toolkit

A container security scanning and reporting toolkit built around **Grype**, with vulnerability analysis, security policy enforcement, historical tracking, comparison reporting, and automated CI/CD integration.

The project is designed to provide a repeatable security pipeline for scanning container images and producing actionable security reports.

## Features

* **Grype vulnerability scanning**

  * Container image vulnerability detection
  * JSON and table scan output
  * Automated vulnerability database updates

* **Security policy enforcement**

  * Configurable severity thresholds
  * Critical/High/Medium/Low vulnerability analysis
  * Automated pass/fail decisions

* **Security scoring**

  * Risk-based security score
  * Severity-weighted vulnerability analysis

* **Reporting**

  * JSON security summaries
  * HTML security reports
  * Scan metadata
  * Historical scan tracking

* **Security comparison**

  * Detect changes between scans
  * Identify new, resolved, and persistent vulnerabilities
  * Track security trends over time

* **Automation**

  * Makefile-based workflow
  * Automated test suite
  * GitHub Actions CI/CD pipeline

* **Corporate environment support**

  * Optional locally supplied corporate CA certificates
  * Local configuration kept outside source control

## Project Structure

```text
container-security/
├── .github/
│   └── workflows/
│       └── security-scan.yml
├── config/
│   ├── config.env.example
│   └── security_policy.yml
├── lib/
│   ├── comparison.py
│   ├── history.py
│   ├── policy.py
│   ├── reporting.py
│   ├── security.py
│   ├── trends.py
│   └── templates/
│       └── report.html.j2
├── scripts/
│   ├── common.sh
│   ├── report.py
│   ├── scan.sh
│   ├── summarize.py
│   └── validate.sh
├── tests/
├── Dockerfile
├── Makefile
├── README.md
└── requirements.txt
```

Generated scan artifacts such as reports, SBOMs, logs, caches, and local configuration are intentionally excluded from source control.

## Requirements

* macOS or Linux
* Python 3
* Docker
* Git
* Grype container image
* Bash

## Setup

Clone the repository and create a Python virtual environment:

```bash
git clone https://github.com/jds-cyber/container-security-toolkit.git
cd container-security-toolkit

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install -r requirements.txt
```

### Local Configuration

Create a local configuration file from the example:

```bash
cp config/config.env.example config/config.env
```

`config/config.env` is intentionally excluded from Git because it may contain environment-specific configuration.

For environments requiring a corporate CA certificate, place the certificate under `certs/` and update `CERT_FILE` in the local configuration.

Corporate certificates and other private credentials should never be committed to the repository.

## Running a Scan

The primary workflow can be run through the Makefile.

```bash
make scan IMAGE=pywinrm-ansible:dev
```

The scan will:

1. Validate the local environment
2. Update the Grype vulnerability database
3. Scan the specified container image
4. Generate scan artifacts
5. Store the scan in the reports directory

## Generate a Summary

After scanning:

```bash
make summarize
```

This generates:

```text
reports/latest/summary.json
```

The summary contains vulnerability counts and the calculated security score.

## Generate an HTML Report

```bash
make report
```

The generated report is written to:

```text
reports/latest/report.html
```

The report contains scan metadata, policy status, vulnerability information, and security scoring.

## Run the Complete Security Workflow

The complete local workflow can be run with:

```bash
make security-report IMAGE=pywinrm-ansible:dev
```

This performs the scan, summary generation, and HTML report generation as a single workflow.

## Run Tests

The project includes automated tests covering scanning logic, policy evaluation, reporting, history, comparisons, and trends.

```bash
pytest
```

The test suite should pass before changes are committed.

## Security Policy

Security thresholds are defined in:

```text
config/security_policy.yml
```

The policy determines whether a scan passes or fails based on vulnerability severity.

A policy failure does **not** necessarily mean that report generation must stop. The pipeline is designed to preserve the scan results and generate reporting artifacts even when security thresholds are exceeded.

## CI/CD

GitHub Actions automatically executes the security workflow defined in:

```text
.github/workflows/security-scan.yml
```

The workflow:

1. Checks out the repository
2. Builds/scans the target image
3. Generates a vulnerability summary
4. Generates the HTML security report
5. Uploads security artifacts
6. Enforces the configured security policy

The pipeline is designed so that security-policy failures are visible while preserving the generated reporting artifacts.

## Security and Secrets

This repository is intended to contain source code and configuration templates, **not private credentials or corporate certificates**.

The following are excluded from Git:

```text
config/config.env
certs/*.crt
certs/*.pem
certs/*.key
reports/
logs/
sbom/
cache/
.venv/
```

Use `config/config.env.example` as the starting point for local configuration.

## Development Workflow

The project is developed incrementally using phased changes.

Before committing changes:

```bash
pytest
git status
git diff
```

For staged changes:

```bash
git diff --cached
```

Keep commits focused on a specific feature or improvement.

Example:

```text
Phase 18: Improve documentation and developer setup
```

## Roadmap

Planned areas of development include:

* Improved vulnerability trend visualization
* Enhanced historical reporting
* SBOM generation and analysis
* Additional container security checks
* Expanded policy controls
* Improved CI/CD integration
* Container image comparison
* Security metrics and dashboards
* Additional automated security tests
* Improved developer documentation

## Project Status

This project is actively being developed as a practical container-security engineering project.

The current implementation provides a working vulnerability scanning, policy enforcement, reporting, comparison, and CI/CD pipeline using Grype.

## License

License information will be added as the project is prepared for broader publication.
