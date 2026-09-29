# Container Security Toolkit

A container security scanning and reporting toolkit built around **Grype**, with vulnerability analysis, SBOM generation and correlation, security policy enforcement, historical tracking, image comparison, security intelligence, and automated CI/CD integration.

The project provides a repeatable security pipeline for scanning container images, analyzing vulnerabilities, generating security reports, and enforcing security policies.

## Features

* **Container vulnerability scanning**

  * Grype-based container image scanning
  * JSON and table scan output
  * Automated vulnerability database updates
  * Scanner-neutral vulnerability model

* **SBOM support**

  * Syft-based SBOM generation
  * Package inventory tracking
  * Vulnerability-to-package correlation
  * Package inventory comparison between scans

* **Vulnerability intelligence**

  * CVSS scoring
  * EPSS scoring
  * OSV vulnerability intelligence
  * External intelligence enrichment
  * Support for CVE, GHSA, and Go vulnerability identifiers

* **Security analysis**

  * Severity-based vulnerability analysis
  * Risk-weighted security scoring
  * Security grades and risk levels
  * Additional container security checks

* **Security policy enforcement**

  * Configurable vulnerability thresholds
  * Critical/High/Medium/Low severity controls
  * CVSS and EPSS policy controls
  * Unfixed vulnerability controls
  * Metadata quality controls

* **Reporting**

  * JSON security summaries
  * HTML security reports
  * Scan metadata
  * Security score and risk information
  * Historical scan tracking
  * Previous-scan comparison

* **Image comparison**

  * Compare security scores
  * Compare vulnerability changes
  * Compare severity changes
  * Compare vulnerability intelligence
  * Compare package inventories
  * Identify added, removed, and persistent findings

* **Automation**

  * Makefile-based workflow
  * Automated test suite
  * GitHub Actions CI/CD pipeline
  * Security artifacts retained from CI runs

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
│   ├── container_checks.py
│   ├── epss.py
│   ├── history.py
│   ├── intelligence.py
│   ├── osv.py
│   ├── policy.py
│   ├── reporting.py
│   ├── sbom.py
│   ├── scanner.py
│   ├── security.py
│   ├── vulnerability.py
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
* Grype
* Syft
* Bash

Python dependencies are defined in:

```text
requirements.txt
```

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

## Makefile Workflow

The primary local workflow is provided through the Makefile.

### Install dependencies

```bash
make install
```

### Run tests

```bash
make test
```

### Scan an image

```bash
make scan IMAGE=pywinrm-ansible:dev
```

### Generate a summary

```bash
make summarize
```

### Generate an HTML report

```bash
make report
```

### Run the complete security workflow

```bash
make security-report IMAGE=pywinrm-ansible:dev
```

The complete workflow performs the scan, generates the security summary, and produces the HTML report.

## Vulnerability Summary

The summary CLI accepts a scanner report and requires the scanner that produced it:

```bash
./scripts/summarize.py \
  reports/latest/report.json \
  --scanner grype
```

The resulting summary is written to:

```text
reports/latest/summary.json
```

The summary includes vulnerability counts, security scoring, risk information, and policy results.

### SBOM Correlation

A Syft SBOM can be supplied to correlate vulnerabilities with installed packages:

```bash
./scripts/summarize.py \
  reports/latest/report.json \
  --scanner grype \
  --sbom reports/latest/sbom.json
```

### Security Policy

A policy can be supplied explicitly:

```bash
./scripts/summarize.py \
  reports/latest/report.json \
  --scanner grype \
  --policy config/security_policy.yml
```

### Vulnerability Intelligence

External vulnerability intelligence can be supplied through an intelligence file:

```bash
./scripts/summarize.py \
  reports/latest/report.json \
  --scanner grype \
  --intelligence intelligence.json
```

OSV and EPSS enrichment can also be requested directly:

```bash
./scripts/summarize.py \
  reports/latest/report.json \
  --scanner grype \
  --osv \
  --epss
```

These options allow vulnerability findings to be enriched with additional information without coupling the core vulnerability model to a specific intelligence provider.

## HTML Reporting

Generate an HTML report from a completed security summary:

```bash
./scripts/report.py \
  reports/latest/summary.json \
  reports/latest/report.html \
  pywinrm-ansible:dev
```

The report includes:

* Scan metadata
* Vulnerability findings
* Severity distribution
* Security score
* Risk level and grade
* Policy status
* Historical information
* Previous-scan comparison
* Package inventory comparison when previous SBOM data is available

The generated report is written to:

```text
reports/latest/report.html
```

## Historical Tracking and Comparison

The toolkit can retain scan history and compare a current scan with a previous scan.

Comparisons include:

* Security score changes
* New vulnerabilities
* Resolved vulnerabilities
* Persistent vulnerabilities
* Severity changes
* Vulnerability intelligence changes
* Added packages
* Removed packages
* Unchanged packages

This provides a way to track whether the security posture of an image is changing over time rather than evaluating each scan in isolation.

## Security Policy

Security thresholds are defined in:

```text
config/security_policy.yml
```

Example:

```yaml
policy:
  max_critical: 0
  max_high: 10
  max_medium: 100
  max_unfixed_vulnerabilities: 0
  max_high_cvss: 0
  max_high_epss: 0
  max_metadata_issues: 0

fail_on:
  - Critical
```

Policy evaluation is separate from report generation.

A policy failure can still produce a security summary and HTML report. In CI/CD, the workflow preserves those artifacts and then enforces the policy as a final step.

## CI/CD

GitHub Actions automatically executes the security workflow defined in:

```text
.github/workflows/security-scan.yml
```

The workflow:

1. Checks out the repository
2. Installs Python dependencies
3. Runs the automated test suite
4. Builds the target container image
5. Installs and runs Grype
6. Generates the vulnerability summary
7. Generates the HTML security report
8. Uploads security artifacts
9. Enforces the configured security policy

The CI workflow specifies the scanner used to generate the vulnerability report so the summary process can remain scanner-aware.

Security-policy failures are reported separately from report generation so scan results and diagnostic artifacts remain available.

## Testing

The project includes automated tests covering:

* Vulnerability modeling and validation
* CVSS and EPSS handling
* Vulnerability intelligence
* OSV integration
* SBOM generation and correlation
* Container security checks
* Security policy evaluation
* Security scoring
* Historical tracking
* Image comparison
* Package comparison
* Reporting
* CLI behavior
* CI workflow configuration
* Integration and security coverage

Run the complete test suite with:

```bash
pytest
```

Tests should pass before changes are committed.

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

Never commit:

* Passwords
* API keys
* Access tokens
* Private certificates
* Private keys
* Corporate credentials

## Development Workflow

Development is organized into focused phases so that changes can be implemented and validated incrementally.

Before committing changes:

```bash
pytest
git status
git diff
git diff --check
```

For staged changes:

```bash
git diff --cached
```

Keep commits focused on a specific feature or improvement.

Example:

```text
Phase 95: Update project documentation
```

## Project Status

The project is being prepared for the **1.0 release**.

The 1.0 roadmap includes:

* SBOM foundation
* SBOM vulnerability correlation
* Container security checks
* Security policy expansion
* Image-to-image comparison
* CI/CD hardening
* Reporting and trend improvements
* Integration and security testing
* Documentation
* Release candidate validation
* Final 1.0 readiness audit

After the 1.0 readiness audit, development transitions from roadmap-driven feature expansion to normal maintenance and security updates.
