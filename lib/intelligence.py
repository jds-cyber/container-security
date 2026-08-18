from abc import ABC, abstractmethod
from datetime import datetime
from lib.vulnerability import (
    VulnerabilityIntelligence,
    CVSS,
    _validate_vulnerability_id,
)


class IntelligenceProvider(ABC):
    """
    Abstract interface for vulnerability intelligence providers.
    """

    @property
    @abstractmethod
    def name(self):
        """
        Name of the intelligence provider.
        """
        raise NotImplementedError

    @abstractmethod
    def get(self, vulnerability_id):
        """
        Retrieve intelligence for a vulnerability.

        Args:
            vulnerability_id: Vulnerability identifier such as CVE-2026-1234 or GHSA-abcd-1234-wxyz.

        Returns:
            VulnerabilityIntelligence or None
        """
        raise NotImplementedError


class StaticIntelligenceProvider(IntelligenceProvider):
    """
    Provides vulnerability intelligence from a static in-memory dataset.
    """

    @property
    def name(self):
        return "static"

    def __init__(self, intelligence=None):
        self.intelligence = intelligence

    def get(self, vulnerability_id):
        vulnerability_id = _validate_vulnerability_id(
            vulnerability_id
        )

        if self.intelligence is None:
            return None

        if self.intelligence.vulnerability_id != vulnerability_id:
            return None

        return self.intelligence


class RecordIntelligenceProvider(IntelligenceProvider):
    """
    Intelligence provider backed by normalized records.

    Intended for testing provider behavior without external services.
    """

    @property
    def name(self):
        return "record"

    def __init__(self, records=None):
        self.records = records or {}

    def get(self, vulnerability_id):
        vulnerability_id = _validate_vulnerability_id(
            vulnerability_id
        )

        record = self.records.get(vulnerability_id)

        if record is None:
            return None

        # CVSS deserialization
        cvss_data = record.get("cvss")
        cvss = None

        if cvss_data is not None:
            cvss = CVSS(
                version=cvss_data["version"],
                score=cvss_data["score"],
                vector=cvss_data.get("vector"),
                severity=cvss_data.get("severity"),
            )

        # Published & Modified deserialization
        published_data = record.get("published")
        published = None

        if published_data is not None:
            published = datetime.fromisoformat(published_data)

        modified_data = record.get("modified")
        modified = None

        if modified_data is not None:
            modified = datetime.fromisoformat(modified_data)

        return VulnerabilityIntelligence(
            vulnerability_id=record["vulnerability_id"],
            description=record.get("description"),
            cvss=cvss,
            cwe=record.get("cwe"),
            published=published,
            modified=modified,
            references=record.get("references"),

        )


def enrich_vulnerabilities(vulnerabilities, provider):
    for vulnerability in vulnerabilities:
        vulnerability.load_intelligence(provider)
