from abc import ABC, abstractmethod
from datetime import datetime
from lib.vulnerability import (
    VulnerabilityIntelligence,
    CVSS,
    AffectedPackage,
    _validate_vulnerability_id,
)
from lib.osv import OSVClient


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

        if not isinstance(record, dict):
            raise ValueError(
                "Intelligence record must be a dictionary."
            )

        record_vulnerability_id = record.get("vulnerability_id")

        if record_vulnerability_id is None:
            raise ValueError(
                "Intelligence record is missing vulnerability_id."
            )

        record_vulnerability_id = _validate_vulnerability_id(
            record_vulnerability_id
        )

        if record_vulnerability_id != vulnerability_id:
            raise ValueError(
                "Intelligence record vulnerability ID does not match "
                "requested vulnerability ID."
            )

        # CVSS deserialization
        cvss_data = record.get("cvss")
        cvss = None

        if cvss_data is not None:
            if not isinstance(cvss_data, dict):
                raise ValueError(
                    "Intelligence record CVSS must be a dictionary."
                )

            try:
                cvss = CVSS(
                    version=cvss_data["version"],
                    score=cvss_data["score"],
                    vector=cvss_data.get("vector"),
                    severity=cvss_data.get("severity"),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    "Invalid intelligence record CVSS data."
                ) from exc

        # Published deserialization
        published_data = record.get("published")
        published = None

        if published_data is not None:
            if not isinstance(published_data, str):
                raise ValueError(
                    "Intelligence record published must be an ISO "
                    "formatted datetime string."
                )

            try:
                published = datetime.fromisoformat(
                    published_data
                )
            except ValueError as exc:
                raise ValueError(
                    "Invalid intelligence record published datetime."
                ) from exc

        # Modified deserialization
        modified_data = record.get("modified")
        modified = None

        if modified_data is not None:
            if not isinstance(modified_data, str):
                raise ValueError(
                    "Intelligence record modified must be an ISO "
                    "formatted datetime string."
                )

            try:
                modified = datetime.fromisoformat(
                    modified_data
                )
            except ValueError as exc:
                raise ValueError(
                    "Invalid intelligence record modified datetime."
                ) from exc

        # AffectedPackage deserialization
        affected_packages_data = record.get(
            "affected_packages"
        )

        affected_packages = None

        if affected_packages_data is not None:
            if not isinstance(affected_packages_data, list):
                raise ValueError(
                    "Intelligence record affected_packages "
                    "must be a list."
                )

            affected_packages = []

            for package in affected_packages_data:
                if not isinstance(package, dict):
                    raise ValueError(
                        "Intelligence record affected_packages "
                        "must contain dictionaries."
                    )

                try:
                    affected_packages.append(
                        AffectedPackage(
                            ecosystem=package["ecosystem"],
                            name=package["name"],
                        )
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValueError(
                        "Invalid intelligence record affected package."
                    ) from exc

        try:
            return VulnerabilityIntelligence(
                vulnerability_id=record_vulnerability_id,
                description=record.get("description"),
                cvss=cvss,
                cwe=record.get("cwe"),
                published=published,
                modified=modified,
                references=record.get("references"),
                aliases=record.get("aliases"),
                affected_packages=affected_packages,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Invalid intelligence record."
            ) from exc


def _convert_osv_datetime(value):
    """
    Convert an OSV timestamp into a datetime.
    """

    if not value:
        return None

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except (TypeError, ValueError):
        return None


def _convert_osv_cvss(severity_data):
    """
    Convert an OSV CVSS severity record into a CVSS object.
    """

    if not severity_data:
        return None

    for severity in severity_data:
        if severity.get("type") != "CVSS_V3":
            continue

        vector = severity.get("score")
        base_score = severity.get("base_score")

        if not vector or base_score is None:
            continue

        if not isinstance(vector, str):
            continue

        if not vector.startswith("CVSS:"):
            continue

        version = vector.split("/", 1)[0].replace(
            "CVSS:",
            "",
        )

        if version not in {"3.0", "3.1"}:
            continue

        try:
            score = float(base_score)
        except (TypeError, ValueError):
            continue

        if score >= 9.0:
            severity_name = "critical"
        elif score >= 7.0:
            severity_name = "high"
        elif score >= 4.0:
            severity_name = "medium"
        elif score >= 0.0:
            severity_name = "low"
        else:
            severity_name = "none"

        return CVSS(
            version=version,
            score=score,
            vector=vector,
            severity=severity_name,
        )

    return None


class OSVIntelligenceProvider(IntelligenceProvider):
    """
    Vulnerability intelligence provider backed by the OSV API.
    """

    @property
    def name(self):
        return "osv"

    def __init__(self, client=None):
        self.client = client or OSVClient()
        self._cache = {}

    def get(self, vulnerability_id):
        vulnerability_id = _validate_vulnerability_id(
            vulnerability_id
        )

        if vulnerability_id in self._cache:
            return self._cache[vulnerability_id]

        record = self.client.get(vulnerability_id)

        if record is None:
            self._cache[vulnerability_id] = None
            return None

        cvss = _convert_osv_cvss(
            record.get("severity")
        )

        intelligence = VulnerabilityIntelligence(
            vulnerability_id=vulnerability_id,
            description=record.get("details") or record.get("summary"),
            cvss=cvss,
            cwe=record.get(
                "database_specific",
                {}
            ).get("cwe_ids"),
            published=_convert_osv_datetime(
                record.get("published"),
            ),
            modified=_convert_osv_datetime(
                record.get("modified")
            ),
            references=[
                reference["url"]
                for reference in record.get("references", [])
                if reference.get("url")
            ],
            aliases=record.get("aliases"),
        )

        self._cache[vulnerability_id] = intelligence

        return intelligence


def enrich_vulnerabilities(vulnerabilities, provider):
    for vulnerability in vulnerabilities:
        vulnerability.load_intelligence(provider)
