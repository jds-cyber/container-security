import json
from abc import ABC, abstractmethod
from lib.vulnerability import Vulnerability


class ScannerAdapter(ABC):
    """
    Abstract interface for scanner report adapters.
    """

    @property
    @abstractmethod
    def name(self):
        """
        Name of the scanner.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def formats(self):
        """
        Report formats supported by this scanner.
        """
        raise NotImplementedError

    @abstractmethod
    def parse(self, report):
        """
        Parse a scanner report into normalized Vulnerability objects.

        Returns:
            list[Vulnerability]
        """
        raise NotImplementedError


class GrypeAdapter(ScannerAdapter):
    """
    Adapter for Grype vulnerability reports.
    """

    @property
    def name(self):
        return "grype"

    @property
    def formats(self):
        return ["json"]

    def parse(self, report):
        if not isinstance(report, dict) or "matches" not in report:
            raise ValueError("Invalid Grype report structure")

        vulnerabilities = []

        for match in report.get("matches", []):
            vulnerability = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            vulnerability_id = vulnerability.get("id")

            if not vulnerability_id:
                continue

            vulnerabilities.append(
                Vulnerability(
                    vulnerability_id=vulnerability_id,
                    severity=vulnerability.get(
                        "severity",
                        "unknown",
                    ).lower(),
                    package=artifact.get("name"),
                    installed_version=artifact.get("version"),
                    fixed_version=(
                        vulnerability.get(
                            "fix",
                            {}
                        ).get(
                            "versions",
                            [None],
                        )[0]
                        if vulnerability.get("fix")
                        else None
                    ),
                )
            )

        return vulnerabilities


class ScannerRegistry:
    """
    Registry of scanner adapters.
    """

    def __init__(self):
        self.adapters = {}

    def register(self, adapter):
        if not isinstance(adapter, ScannerAdapter):
            raise ValueError("adapter must be a ScannerAdapter")

        if not adapter.name:
            raise ValueError("adapter must have a name")

        self.adapters[adapter.name] = adapter

    def get(self, scanner):
        return self.adapters.get(scanner)


def create_default_registry():
    """
    Create a registry containing the built-in scanner adapters.
    """

    registry = ScannerRegistry()
    registry.register(GrypeAdapter())

    return registry


def parse_scan(registry, scanner, report):
    """
    Parse a scanner report using the registered scanner adapter.
    """

    adapter = registry.get(scanner)

    if adapter is None:
        raise ValueError(
            "Unknown scanner: {}".format(scanner)
        )

    return adapter.parse(report)


def load_scan_report(registry, scanner, report_path):
    """
    Load a scanner report from disk based on the scanner adapter's supported formats.
    """

    adapter = registry.get(scanner)

    if adapter is None:
        raise ValueError(
            "Unknown scanner: {}".format(scanner)
        )

    report_format = report_path.suffix.lstrip(".").lower()

    if report_format not in adapter.formats:
        raise ValueError(
            "Unsupported report format: {}".format(
                report_format
            )
        )

    if report_format == "json":
        try:
            with open(report_path) as f:
                return json.load(f)

        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSON report") from exc

    raise ValueError(
        "Unsupported report format: {}".format(report_format)
    )
