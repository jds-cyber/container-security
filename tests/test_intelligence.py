import pytest
from datetime import datetime

from lib.vulnerability import (
    Vulnerability,
    VulnerabilityIntelligence,
    CVSS,
    EPSS,
)
from lib.intelligence import (
    IntelligenceProvider,
    StaticIntelligenceProvider,
    RecordIntelligenceProvider,
    OSVIntelligenceProvider,
    EPSSIntelligenceProvider,
    enrich_vulnerabilities,
    _convert_osv_cvss,
)


# ---------------------------------------------------------------------------
# IntelligenceProvider
# ---------------------------------------------------------------------------

class TestProvider(IntelligenceProvider):

    @property
    def name(self):
        return "static"

    def get(self, vulnerability_id):
        return VulnerabilityIntelligence(
            vulnerability_id=vulnerability_id,
            description="Example vulnerability",
        )


def test_intelligence_provider_get_returns_intelligence():

    provider = TestProvider()

    result = provider.get("CVE-2014-0160")

    assert isinstance(result, VulnerabilityIntelligence)
    assert result.vulnerability_id == "CVE-2014-0160"


def test_intelligence_provider_cannot_be_instantiated():

    with pytest.raises(TypeError):
        IntelligenceProvider()


def test_intelligence_provider_requires_get_implemented():

    class TestProvider(IntelligenceProvider):
        pass

    with pytest.raises(TypeError):
        TestProvider()


def test_intelligence_provider_get_returns_none_when_not_found():

    class TestProvider(IntelligenceProvider):

        @property
        def name(self):
            return "static"

        def get(self, vulnerability_id):
            return None

    provider = TestProvider()

    result = provider.get("CVE-2026-9999")

    assert result is None


def test_intelligence_provider_get_receives_vulnerability_id():

    class TestProvider(IntelligenceProvider):

        def __init__(self):
            self.received_id = None

        @property
        def name(self):
            return "static"

        def get(self, vulnerability_id):
            self.received_id = vulnerability_id
            return None

    provider = TestProvider()

    provider.get("CVE-2026-1234")

    assert provider.received_id == "CVE-2026-1234"


def test_intelligence_provider_requires_name_implementation():

    class TestProvider(IntelligenceProvider):

        def get(self, vulnerability_id):
            return None

    with pytest.raises(TypeError):
        TestProvider()


# ---------------------------------------------------------------------------
# StaticIntelligenceProvider
# ---------------------------------------------------------------------------

def test_static_intelligence_provider_returns_intelligence():

    intelligence = VulnerabilityIntelligence(
        "CVE-2026-20349",
        description="Cisco heap-based vulnerability.",
    )

    provider = StaticIntelligenceProvider(
        intelligence=intelligence,
    )

    result = provider.get("CVE-2026-20349")

    assert result is intelligence


def test_static_intelligence_provider_returns_none_for_different_id():

    intelligence = VulnerabilityIntelligence(
        "CVE-2026-1234",
        description="Example vulnerability.",
    )

    provider = StaticIntelligenceProvider(
        intelligence=intelligence,
    )

    result = provider.get("CVE-2026-9999")

    assert result is None


def test_static_intelligence_provider_defaults_to_none():

    provider = StaticIntelligenceProvider()

    result = provider.get("CVE-2026-1234")

    assert result is None


def test_static_intelligence_provider_has_name():

    provider = StaticIntelligenceProvider()

    assert provider.name == "static"


def test_static_intelligence_provider_normalizes_vulnerability_id():

    intelligence = VulnerabilityIntelligence(
        "CVE-2026-1234",
        description="Example vulnerability.",
    )

    provider = StaticIntelligenceProvider(
        intelligence=intelligence,
    )

    result = provider.get("cve-2026-1234")

    assert result is intelligence


def test_static_intelligence_provider_returns_intelligence_for_vulnerability():

    intelligence = VulnerabilityIntelligence(
        "CVE-2017-0199",
        description="Microsoft Wordpad Remote Code Execution Vulnerability",
    )

    provider = StaticIntelligenceProvider(
        intelligence=intelligence,
    )

    vulnerability = Vulnerability(
        "CVE-2017-0199"
    )

    result = provider.get(vulnerability.id)

    assert result is intelligence
    assert result.description == (
        "Microsoft Wordpad Remote Code Execution Vulnerability"
    )


# ---------------------------------------------------------------------------
# RecordIntelligenceProvider
# ---------------------------------------------------------------------------

def test_record_intelligence_provider_returns_intelligence():

    intelligence = VulnerabilityIntelligence(
        "CVE-2021-44228",
        description=(
            "A critical remote code execution (RCE) flaw in the "
            "Apache Log4j Java logging library."
        ),
    )

    provider = RecordIntelligenceProvider(
        records={
            "CVE-2021-44228": intelligence.to_dict()
        }
    )

    result = provider.get("CVE-2021-44228")

    assert isinstance(result, VulnerabilityIntelligence)
    assert result.vulnerability_id == "CVE-2021-44228"
    assert result.description == (
        "A critical remote code execution (RCE) flaw in the "
        "Apache Log4j Java logging library."
    )


def test_record_intelligence_provider_returns_none_when_not_found():

    provider = RecordIntelligenceProvider(
        records={}
    )

    result = provider.get("CVE-2021-44228")

    assert result is None


def test_record_intelligence_provider_preserves_metadata():

    intelligence = VulnerabilityIntelligence(
        "CVE-2014-6271",
        description=(
            "A vulnerability in the GNU Bash shell enabling remote "
            "code execution via environment variables."
        ),
        cwe=["CWE-78"],
        references=[
            "https://nvd.nist.gov/vuln/detail/cve-2014-6271"
        ],
    )

    provider = RecordIntelligenceProvider(
        records={
            "CVE-2014-6271": intelligence.to_dict()
        }
    )

    result = provider.get("CVE-2014-6271")

    assert result.description == (
        "A vulnerability in the GNU Bash shell enabling remote "
        "code execution via environment variables."
    )
    assert result.cwe == ["CWE-78"]
    assert result.references == [
        "https://nvd.nist.gov/vuln/detail/cve-2014-6271"
    ]


def test_record_intelligence_provider_reconstructs_aliases():

    intelligence = VulnerabilityIntelligence(
        "CVE-2021-44228",
        description="Log4Shell",
        aliases=[
            "GHSA-jfh8-c2jp-5v3q",
            "CVE-2021-44228",
        ],
    )

    provider = RecordIntelligenceProvider(
        records={
            "CVE-2021-44228": intelligence.to_dict()
        }
    )

    result = provider.get("CVE-2021-44228")

    assert result.aliases == [
        "GHSA-JFH8-C2JP-5V3Q",
        "CVE-2021-44228",
    ]


def test_record_intelligence_provider_normalizes_vulnerability_id():

    intelligence = VulnerabilityIntelligence(
        "CVE-2026-1234",
        description="Example vulnerability.",
    )

    provider = RecordIntelligenceProvider(
        records={
            "CVE-2026-1234": intelligence.to_dict()
        }
    )

    result = provider.get("cve-2026-1234")

    assert isinstance(result, VulnerabilityIntelligence)
    assert result.vulnerability_id == "CVE-2026-1234"


def test_record_intelligence_provider_reconstructs_cvss():

    cvss = CVSS(
        version="3.1",
        score=9.8,
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="critical",
    )

    intelligence = VulnerabilityIntelligence(
        "CVE-2021-44228",
        description="Log4Shell",
        cvss=cvss,
    )

    provider = RecordIntelligenceProvider(
        records={
            "CVE-2021-44228": intelligence.to_dict()
        }
    )

    result = provider.get("CVE-2021-44228")

    assert isinstance(result.cvss, CVSS)
    assert result.cvss.version == "3.1"
    assert result.cvss.score == 9.8
    assert result.cvss.severity == "critical"


def test_record_intelligence_provider_reconstructs_full_intelligence():

    cvss = CVSS(
        version="3.1",
        score=8.8,
        vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity="high",
    )

    intelligence = VulnerabilityIntelligence(
        "CVE-2017-0144",
        description="WannaCry",
        cvss=cvss,
        cwe=["CWE-119"],
        published=datetime(2017, 3, 17, 0, 0, 0),
        modified=datetime(2017, 4, 14, 0, 0, 0),
        references=[
            "https://nvd.nist.gov/vuln/detail/cve-2017-0144"
        ],
    )

    provider = RecordIntelligenceProvider(
        records={
            "CVE-2017-0144": intelligence.to_dict()
        }
    )

    result = provider.get("CVE-2017-0144")

    assert result.vulnerability_id == "CVE-2017-0144"
    assert result.description == "WannaCry"

    assert isinstance(result.cvss, CVSS)
    assert result.cvss.score == 8.8
    assert result.cvss.severity == "high"

    assert result.cwe == ["CWE-119"]
    assert result.published == datetime(2017, 3, 17, 0, 0, 0)
    assert result.modified == datetime(2017, 4, 14, 0, 0, 0)
    assert result.references == [
        "https://nvd.nist.gov/vuln/detail/cve-2017-0144"
    ]


# ---------------------------------------------------------------------------
# enrich_vulnerabilities
# ---------------------------------------------------------------------------

def test_enrich_vulnerabilities_loads_intelligence():

    intelligence = VulnerabilityIntelligence(
        "CVE-2017-0144",
        description="Windows SMBv1 Remote Code Execution Vulnerability",
    )

    provider = StaticIntelligenceProvider(
        intelligence=intelligence,
    )

    vulnerabilities = [
        Vulnerability("CVE-2017-0144"),
    ]

    enrich_vulnerabilities(vulnerabilities, provider)

    assert vulnerabilities[0].intelligence is intelligence


def test_enrich_vulnerabilities_loads_intelligence_for_multiple_vulnerabilities():

    intelligence = VulnerabilityIntelligence(
        "CVE-2017-0199",
        description="Microsoft Wordpad Remote Code Execution Vulnerability",
    )

    provider = RecordIntelligenceProvider(
        records={
            "CVE-2017-0199": intelligence.to_dict(),
            "CVE-2012-1723": VulnerabilityIntelligence(
                "CVE-2012-1723",
                description=(
                    "Java Applet Field Bytecode Verifier Cache "
                    "Remote Code Execution"
                ),
            ).to_dict(),
        }
    )

    vulnerabilities = [
        Vulnerability("CVE-2017-0199"),
        Vulnerability("CVE-2012-1723"),
    ]

    enrich_vulnerabilities(vulnerabilities, provider)

    assert vulnerabilities[0].intelligence is not None
    assert vulnerabilities[0].intelligence.vulnerability_id == (
        "CVE-2017-0199"
    )

    assert vulnerabilities[1].intelligence is not None
    assert vulnerabilities[1].intelligence.vulnerability_id == (
        "CVE-2012-1723"
    )


def test_enrich_vulnerabilities_loads_intelligence_for_each_vulnerability():

    intelligence1 = VulnerabilityIntelligence(
        "CVE-2021-44228",
        description="Log4Shell",
    )

    intelligence2 = VulnerabilityIntelligence(
        "CVE-2014-6271",
        description="Shellshock",
    )

    provider = RecordIntelligenceProvider(
        records={
            "CVE-2021-44228": intelligence1.to_dict(),
            "CVE-2014-6271": intelligence2.to_dict(),
        }
    )

    vulnerabilities = [
        Vulnerability("CVE-2021-44228"),
        Vulnerability("CVE-2014-6271"),
    ]

    enrich_vulnerabilities(vulnerabilities, provider)

    assert (
        vulnerabilities[0].intelligence.vulnerability_id
        == intelligence1.vulnerability_id
    )
    assert (
        vulnerabilities[1].intelligence.vulnerability_id
        == intelligence2.vulnerability_id
    )

    assert vulnerabilities[0].intelligence.description == "Log4Shell"
    assert vulnerabilities[1].intelligence.description == "Shellshock"


def test_enrich_vulnerabilities_leaves_intelligence_none_when_not_found():

    provider = RecordIntelligenceProvider(
        records={}
    )

    vulnerabilities = [
        Vulnerability("CVE-2021-34473"),
    ]

    enrich_vulnerabilities(vulnerabilities, provider)

    assert vulnerabilities[0].intelligence is None


def test_enrich_vulnerabilities_handles_empty_list():

    provider = RecordIntelligenceProvider(
        records={}
    )

    vulnerabilities = []

    enrich_vulnerabilities(vulnerabilities, provider)


def test_enrich_vulnerabilities_populates_intelligence():

    intelligence = VulnerabilityIntelligence(
        "CVE-2021-44228",
        description="Log4Shell",
        cwe=["CWE-502"],
    )

    provider = RecordIntelligenceProvider(
        records={
            "CVE-2021-44228": intelligence.to_dict()
        }
    )

    vulnerabilities = [
        Vulnerability("CVE-2021-44228"),
    ]

    enrich_vulnerabilities(vulnerabilities, provider)

    assert vulnerabilities[0].intelligence is not None
    assert (
        vulnerabilities[0].intelligence.vulnerability_id
        == "CVE-2021-44228"
    )
    assert vulnerabilities[0].intelligence.description == "Log4Shell"
    assert vulnerabilities[0].intelligence.cwe == ["CWE-502"]


def test_enrich_vulnerabilities_accepts_multiple_providers():

    osv_intelligence = VulnerabilityIntelligence(
        "CVE-2026-1234",
        description="OSV description",
    )

    epss_intelligence = VulnerabilityIntelligence(
        "CVE-2026-1234",
        epss=EPSS(
            score=0.97,
            percentile=0.999,
        ),
    )

    osv_provider = StaticIntelligenceProvider(
        intelligence=osv_intelligence,
    )

    epss_provider = StaticIntelligenceProvider(
        intelligence=epss_intelligence,
    )

    vulnerabilities = [
        Vulnerability("CVE-2026-1234"),
    ]

    enrich_vulnerabilities(
        vulnerabilities,
        [
            osv_provider,
            epss_provider,
        ],
    )

    intelligence = vulnerabilities[0].intelligence

    assert intelligence.description == "OSV description"
    assert intelligence.epss.score == 0.97
    assert intelligence.epss.percentile == 0.999


def test_enrich_vulnerabilities_applies_providers_in_order():

    first = StaticIntelligenceProvider(
        intelligence=VulnerabilityIntelligence(
            "CVE-2026-1234",
            description="First",
        )
    )

    second = StaticIntelligenceProvider(
        intelligence=VulnerabilityIntelligence(
            "CVE-2026-1234",
            description="Second",
        )
    )

    vulnerabilities = [
        Vulnerability("CVE-2026-1234"),
    ]

    enrich_vulnerabilities(
        vulnerabilities,
        [
            first,
            second,
        ],
    )

    assert vulnerabilities[0].intelligence.description == "Second"


def test_enrich_vulnerabilities_preserves_single_provider_behavior():

    intelligence = VulnerabilityIntelligence(
        "CVE-2026-1234",
        description="Example",
    )

    provider = StaticIntelligenceProvider(
        intelligence=intelligence,
    )

    vulnerabilities = [
        Vulnerability("CVE-2026-1234"),
    ]

    enrich_vulnerabilities(
        vulnerabilities,
        provider,
    )

    assert vulnerabilities[0].intelligence is intelligence


def test_enrich_vulnerabilities_handles_empty_provider_list():

    vulnerabilities = [
        Vulnerability("CVE-2025-1234"),
    ]

    enrich_vulnerabilities(
        vulnerabilities,
        [],
    )

    assert vulnerabilities[0].intelligence is None


def test_enrich_vulnerabilities_accepts_provider_tuple():

    intelligence = VulnerabilityIntelligence(
        "CVE-2025-1234",
        description="Test description",
    )

    provider = StaticIntelligenceProvider(
        intelligence=intelligence,
    )

    vulnerabilities = [
        Vulnerability("CVE-2025-1234"),
    ]

    enrich_vulnerabilities(
        vulnerabilities,
        (provider,),
    )

    assert vulnerabilities[0].intelligence.description == (
        "Test description"
    )


# ---------------------------------------------------------------------------
# OSVIntelligenceProvider
# ---------------------------------------------------------------------------

def test_osv_intelligence_provider_has_name():

    provider = OSVIntelligenceProvider()

    assert provider.name == "osv"


def test_osv_intelligence_provider_normalizes_vulnerability_id():

    class FakeClient:

        def __init__(self):
            self.received_id = None

        def get(self, vulnerability_id):
            self.received_id = vulnerability_id
            return None

    client = FakeClient()

    provider = OSVIntelligenceProvider(
        client=client
    )

    result = provider.get("cve-2026-1234")

    assert result is None
    assert client.received_id == "CVE-2026-1234"


def test_osv_intelligence_provider_returns_none_when_not_found():

    class FakeClient:

        def get(self, vulnerability_id):
            return None

    provider = OSVIntelligenceProvider(
        client=FakeClient()
    )

    result = provider.get("CVE-2026-9999")

    assert result is None


def test_osv_intelligence_provider_converts_osv_record():

    class FakeClient:

        def get(self, vulnerability_id):
            return {
                "id": "CVE-2021-44228",
                "summary": (
                    "Apache Log4j2 remote code execution vulnerability."
                ),
                "details": (
                    "A remote code execution vulnerability in Apache Log4j2."
                ),
                "published": "2021-12-10T10:15:00Z",
                "modified": "2026-08-01T12:00:00Z",
                "aliases": [
                    "CVE-2021-44228",
                ],
                "references": [
                    {
                        "type": "ADVISORY",
                        "url": "https://example.com/advisory",
                    }
                ],
                "database_specific": {
                    "cwe_ids": [
                        "CWE-502",
                    ],
                },
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": (
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                            "S:U/C:H/I:H/A:H"
                        ),
                    }
                ],
            }

    provider = OSVIntelligenceProvider(
        client=FakeClient()
    )

    result = provider.get("CVE-2021-44228")

    assert isinstance(result, VulnerabilityIntelligence)
    assert result.vulnerability_id == "CVE-2021-44228"
    assert result.aliases == [
        "CVE-2021-44228"
    ]
    assert result.description == (
        "A remote code execution vulnerability in Apache Log4j2."
    )
    assert result.cwe == ["CWE-502"]
    assert result.published is not None
    assert result.modified is not None
    assert result.references == [
        "https://example.com/advisory"
    ]


def test_osv_intelligence_provider_uses_summary_when_details_missing():

    class FakeClient:

        def get(self, vulnerability_id):
            return {
                "id": "CVE-2026-1234",
                "summary": "Example OSV vulnerability.",
                "published": "2026-01-15T12:00:00Z",
                "modified": "2026-08-01T12:00:00Z",
                "references": [],
                "database_specific": {},
            }

    provider = OSVIntelligenceProvider(
        client=FakeClient()
    )

    result = provider.get("CVE-2026-1234")

    assert isinstance(result, VulnerabilityIntelligence)
    assert result.description == "Example OSV vulnerability."


def test_osv_intelligence_provider_allows_missing_description():

    class FakeClient:

        def get(self, vulnerability_id):
            return {
                "id": "CVE-2026-1234",
                "published": "2026-01-15T12:00:00Z",
                "modified": "2026-08-01T12:00:00Z",
                "references": [],
                "database_specific": {},
            }

    provider = OSVIntelligenceProvider(
        client=FakeClient()
    )

    result = provider.get("CVE-2026-1234")

    assert isinstance(result, VulnerabilityIntelligence)
    assert result.description is None


def test_osv_intelligence_provider_converts_cvss():

    class FakeClient:

        def get(self, vulnerability_id):
            return {
                "id": "CVE-2021-44228",
                "summary": "Log4Shell",
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": (
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                            "S:U/C:H/I:H/A:H"
                        ),
                        "base_score": 10.0,
                    }
                ],
            }

    provider = OSVIntelligenceProvider(
        client=FakeClient()
    )

    result = provider.get("CVE-2021-44228")

    assert isinstance(result.cvss, CVSS)
    assert result.cvss.version == "3.1"
    assert result.cvss.vector == (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    assert result.cvss.score == 10.0
    assert result.cvss.severity == "critical"


def test_osv_intelligence_provider_allows_missing_database_specific():

    class FakeClient:

        def get(self, vulnerability_id):
            return {
                "id": "CVE-2026-1234",
                "summary": "Example OSV vulnerability.",
            }

    provider = OSVIntelligenceProvider(
        client=FakeClient()
    )

    result = provider.get("CVE-2026-1234")

    assert isinstance(result, VulnerabilityIntelligence)
    assert result.cwe is None


def test_osv_intelligence_provider_skips_references_without_urls():

    class FakeClient:

        def get(self, vulnerability_id):
            return {
                "id": "CVE-2026-1234",
                "summary": "Example OSV vulnerability.",
                "references": [
                    {
                        "type": "PACKAGE",
                    },
                    {
                        "type": "ADVISORY",
                        "url": "https://example.com/advisory",
                    },
                    {
                        "type": "WEB",
                    },
                ],
            }

    provider = OSVIntelligenceProvider(
        client=FakeClient()
    )

    result = provider.get("CVE-2026-1234")

    assert result.references == [
        "https://example.com/advisory"
    ]


# ---------------------------------------------------------------------------
# OSVIntelligenceProvider - date handling
# ---------------------------------------------------------------------------

def test_osv_intelligence_provider_converts_published_and_modified_dates():

    class FakeClient:

        def get(self, vulnerability_id):
            return {
                "id": "CVE-2026-1234",
                "summary": "Example OSV vulnerability.",
                "published": "2026-01-15T12:00:00Z",
                "modified": "2026-08-01T12:30:00Z",
            }

    provider = OSVIntelligenceProvider(
        client=FakeClient()
    )

    result = provider.get("CVE-2026-1234")

    assert result.published == datetime.fromisoformat(
        "2026-01-15T12:00:00+00:00"
    )

    assert result.modified == datetime.fromisoformat(
        "2026-08-01T12:30:00+00:00"
    )


def test_osv_intelligence_provider_allows_missing_dates():

    class FakeClient:

        def get(self, vulnerability_id):
            return {
                "id": "CVE-2026-1234",
                "summary": "Example OSV vulnerability.",
            }

    provider = OSVIntelligenceProvider(
        client=FakeClient()
    )

    result = provider.get("CVE-2026-1234")

    assert isinstance(result, VulnerabilityIntelligence)
    assert result.published is None
    assert result.modified is None


def test_osv_intelligence_provider_skips_malformed_dates():

    class FakeClient:

        def get(self, vulnerability_id):
            return {
                "id": "CVE-2026-1234",
                "summary": "Example OSV vulnerability.",
                "published": "not-a-date",
                "modified": "2026-08-01T12:00:00Z",
            }

    provider = OSVIntelligenceProvider(
        client=FakeClient()
    )

    result = provider.get("CVE-2026-1234")

    assert isinstance(result, VulnerabilityIntelligence)
    assert result.published is None
    assert result.modified == datetime.fromisoformat(
        "2026-08-01T12:00:00+00:00"
    )


def test_osv_intelligence_provider_caches_successful_result():
    class FakeOSVClient:
        def __init__(self):
            self.calls = []

        def get(self, vulnerability_id):
            self.calls.append(vulnerability_id)
            return {
                "details": "Test vulnerability",
                "severity": [],
                "references": [],
                "aliases": [],
            }

    client = FakeOSVClient()
    provider = OSVIntelligenceProvider(client=client)

    first = provider.get("CVE-2026-1234")
    second = provider.get("CVE-2026-1234")

    assert first == second
    assert first is not second
    assert client.calls == [
        "CVE-2026-1234",
    ]


def test_osv_intelligence_provider_caches_missing_result():
    class FakeOSVClient:
        def __init__(self):
            self.calls = []

        def get(self, vulnerability_id):
            self.calls.append(vulnerability_id)
            return None

    client = FakeOSVClient()
    provider = OSVIntelligenceProvider(client=client)

    first = provider.get("CVE-2026-1234")
    second = provider.get("CVE-2026-1234")

    assert first is None
    assert second is None
    assert client.calls == [
        "CVE-2026-1234",
    ]


def test_osv_intelligence_provider_keeps_cache_entries_separate():
    class FakeOSVClient:

        def __init__(self):
            self.calls = []

        def get(self, vulnerability_id):
            self.calls.append(vulnerability_id)

            return {
                "details": vulnerability_id,
                "severity": [],
                "references": [],
                "aliases": [],
            }

    client = FakeOSVClient()
    provider = OSVIntelligenceProvider(client=client)

    first = provider.get("CVE-2026-1234")
    second = provider.get("CVE-2026-5678")
    first_again = provider.get("CVE-2026-1234")

    assert first is not second
    assert first.vulnerability_id != second.vulnerability_id
    assert first.description != second.description

    assert first_again is not first
    assert first_again.vulnerability_id == first.vulnerability_id
    assert first_again.description == first.description

    assert client.calls == [
        "CVE-2026-1234",
        "CVE-2026-5678",
    ]


def test_osv_intelligence_provider_cache_is_not_mutated_by_result_changes():
    class FakeOSVClient:

        def __init__(self):
            self.calls = []

        def get(self, vulnerability_id):
            self.calls.append(vulnerability_id)

            return {
                "details": "Original description",
                "severity": [],
                "references": [],
                "aliases": [],
            }

    client = FakeOSVClient()
    provider = OSVIntelligenceProvider(client=client)

    first = provider.get("CVE-2026-1234")

    first.description = "Modified description"

    second = provider.get("CVE-2026-1234")

    assert second.description == "Original description"
    assert client.calls == [
        "CVE-2026-1234",
    ]


def test_osv_intelligence_provider_cache_is_protected_from_list_mutation():
    class FakeOSVClient:
        def __init__(self):
            self.calls = []

        def get(self, vulnerability_id):
            self.calls.append(vulnerability_id)

            return {
                "details": "Original description",
                "severity": [],
                "database_specific": {
                    "cwe_ids": ["CWE-79"],
                },
                "references": [
                    {"url": "https://example.com/advisory"},
                ],
                "aliases": ["GHSA-1234"],
            }

    client = FakeOSVClient()
    provider = OSVIntelligenceProvider(client=client)

    first = provider.get("CVE-2026-1234")

    first.cwe.append("CWE-89")
    first.references.append("https://example.com/second")
    first.aliases.append("GHSA-5678")

    second = provider.get("CVE-2026-1234")

    assert second.cwe == ["CWE-79"]
    assert second.references == ["https://example.com/advisory"]
    assert second.aliases == ["GHSA-1234"]
    assert client.calls == ["CVE-2026-1234"]

# ---------------------------------------------------------------------------
# EPSSIntelligenceProvider
# ---------------------------------------------------------------------------

def test_epss_intelligence_provider_has_name():

    class FakeClient:

        def get(self, vulnerability_id):
            return None

    provider = EPSSIntelligenceProvider(
        client=FakeClient()
    )

    assert provider.name == "epss"


def test_epss_intelligence_provider_normalizes_vulnerability_id():

    class FakeClient:

        def __init__(self):
            self.received_id = None

        def get(self, vulnerability_id):
            self.received_id = vulnerability_id
            return None

    client = FakeClient()

    provider = EPSSIntelligenceProvider(
        client=client
    )

    result = provider.get("cve-2026-1234")

    assert result is None
    assert client.received_id == "CVE-2026-1234"


def test_epss_intelligence_provider_returns_none_when_not_found():

    class FakeClient:

        def get(self, vulnerability_id):
            return None

    provider = EPSSIntelligenceProvider(
        client=FakeClient()
    )

    result = provider.get("CVE-2026-1234")

    assert result is None


def test_epss_intelligence_provider_converts_epss_record():

    class FakeClient:

        def get(self, vulnerability_id):
            return {
                "cve": "CVE-2026-1234",
                "epss": "0.972240000",
                "percentile": "1.000000000",
                "date": "2026-09-06",
            }

    provider = EPSSIntelligenceProvider(
        client=FakeClient()
    )

    result = provider.get("CVE-2026-1234")

    assert isinstance(result, VulnerabilityIntelligence)
    assert result.vulnerability_id == "CVE-2026-1234"
    assert result.description is None
    assert result.cvss is None
    assert result.cwe is None
    assert result.epss is not None
    assert result.epss.score == 0.97224
    assert result.epss.percentile == 1.0
    assert result.epss.date == datetime(2026, 9, 6, 0, 0, 0)


def test_epss_intelligence_provider_caches_result():

    class FakeClient:

        def __init__(self):
            self.calls = []

        def get(self, vulnerability_id):
            self.calls.append(vulnerability_id)

            return {
                "cve": vulnerability_id,
                "epss": "0.5",
                "percentile": "0.75",
                "date": "2026-09-06",
            }

    client = FakeClient()

    provider = EPSSIntelligenceProvider(
        client=client
    )

    first = provider.get("CVE-2026-1234")
    second = provider.get("CVE-2026-1234")

    assert first == second
    assert first is not second
    assert client.calls == [
        "CVE-2026-1234"
    ]


def test_epss_intelligence_provider_caches_missing_result():

    class FakeClient:

        def __init__(self):
            self.calls = []

        def get(self, vulnerability_id):
            self.calls.append(vulnerability_id)
            return None

    client = FakeClient()

    provider = EPSSIntelligenceProvider(
        client=client
    )

    first = provider.get("CVE-2026-1234")
    second = provider.get("CVE-2026-1234")

    assert first is None
    assert second is None
    assert client.calls == [
        "CVE-2026-1234"
    ]


def test_epss_intelligence_provider_rejects_invalid_score():

    class FakeClient:

        def get(self, vulnerability_id):
            return {
                "cve": "CVE-2026-1234",
                "epss": "not-a-score",
                "percentile": "0.75",
                "date": "2026-09-06",
            }

    provider = EPSSIntelligenceProvider(
        client=FakeClient()
    )

    with pytest.raises(
        ValueError,
        match="Invalid EPSS score data"
    ):
        provider.get("CVE-2026-1234")


def test_epss_intelligence_provider_rejects_invalid_date():

    class FakeClient:

        def get(self, vulnerability_id):
            return {
                "cve": "CVE-2026-1234",
                "epss": "0.5",
                "percentile": "0.75",
                "date": "not-a-date",
            }

    provider = EPSSIntelligenceProvider(
        client=FakeClient()
    )

    with pytest.raises(
        ValueError,
        match="Invalid EPSS date"
    ):
        provider.get("CVE-2026-1234")


def test_epss_intelligence_provider_caches_successful_result():
    class FakeEPSSClient:
        def __init__(self):
            self.calls = []

        def get(self, vulnerability_id):
            self.calls.append(vulnerability_id)
            return {
                "cve": vulnerability_id,
                "epss": "0.72",
                "percentile": "0.91",
                "date": "2026-09-01",
            }

    client = FakeEPSSClient()
    provider = EPSSIntelligenceProvider(client=client)

    first = provider.get("CVE-2026-1234")
    second = provider.get("CVE-2026-1234")

    assert first == second
    assert first is not second
    assert client.calls == [
        "CVE-2026-1234",
    ]


def test_epss_intelligence_provider_caches_missing_result():
    class FakeEPSSClient:
        def __init__(self):
            self.calls = []

        def get(self, vulnerability_id):
            self.calls.append(vulnerability_id)
            return None

    client = FakeEPSSClient()
    provider = EPSSIntelligenceProvider(client=client)

    first = provider.get("CVE-2026-1234")
    second = provider.get("CVE-2026-1234")

    assert first is None
    assert second is None
    assert client.calls == [
        "CVE-2026-1234",
    ]


def test_epss_intelligence_provider_keeps_cache_entries_separate():
    class FakeEPSSClient:

        def __init__(self):
            self.calls = []

        def get(self, vulnerability_id):
            self.calls.append(vulnerability_id)

            return {
                "cve": vulnerability_id,
                "epss": "0.72",
                "percentile": "0.91",
                "date": "2026-09-01",
            }

    client = FakeEPSSClient()
    provider = EPSSIntelligenceProvider(client=client)

    first = provider.get("CVE-2026-1234")
    second = provider.get("CVE-2026-5678")
    first_again = provider.get("CVE-2026-1234")

    assert first is not second
    assert first.vulnerability_id != second.vulnerability_id

    assert first_again is not first
    assert first_again.vulnerability_id == first.vulnerability_id
    assert first_again.epss.score == first.epss.score
    assert first_again.epss.percentile == first.epss.percentile

    assert client.calls == [
        "CVE-2026-1234",
        "CVE-2026-5678",
    ]


def test_epss_intelligence_provider_cache_is_not_mutated_by_result_changes():
    class FakeEPSSClient:

        def __init__(self):
            self.calls = []

        def get(self, vulnerability_id):
            self.calls.append(vulnerability_id)

            return {
                "cve": vulnerability_id,
                "epss": "0.72",
                "percentile": "0.91",
                "date": "2026-09-01",
            }

    client = FakeEPSSClient()
    provider = EPSSIntelligenceProvider(client=client)

    first = provider.get("CVE-2026-1234")

    first.epss.score = 0.01

    second = provider.get("CVE-2026-1234")

    assert second.epss.score == 0.72
    assert client.calls == [
        "CVE-2026-1234",
    ]

# ---------------------------------------------------------------------------
# _convert_osv_cvss
# ---------------------------------------------------------------------------

def test_convert_osv_cvss_returns_none_when_missing():

    result = _convert_osv_cvss(None)

    assert result is None


def test_convert_osv_cvss_returns_none_for_non_list():

    result = _convert_osv_cvss(
        {"type": "CVSS_V3"}
    )

    assert result is None


def test_convert_osv_cvss_returns_none_for_empty_list():

    result = _convert_osv_cvss([])

    assert result is None


def test_convert_osv_cvss_skips_non_dictionary_entries():

    severity_data = [
        "invalid",
        None,
        123,
        {
            "type": "CVSS_V3",
            "score": (
                "CVSS:3.1/"
                "AV:N/AC:L/PR:N/UI:N/"
                "S:U/C:H/I:H/A:H"
            ),
            "base_score": 9.8,
        },
    ]

    result = _convert_osv_cvss(severity_data)

    assert isinstance(result, CVSS)
    assert result.version == "3.1"
    assert result.score == 9.8


def test_convert_osv_cvss_converts_cvss_v3():

    severity_data = [
        {
            "type": "CVSS_V3",
            "score": (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                "S:U/C:H/I:H/A:H"
            ),
            "base_score": 10.0,
        }
    ]

    result = _convert_osv_cvss(severity_data)

    assert isinstance(result, CVSS)
    assert result.version == "3.1"
    assert result.score == 10.0
    assert result.vector == (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    assert result.severity == "critical"


def test_convert_osv_cvss_skips_non_cvss_v3():

    severity_data = [
        {
            "type": "OTHER",
            "score": "something",
            "base_score": 10.0,
        }
    ]

    result = _convert_osv_cvss(severity_data)

    assert result is None


def test_convert_osv_cvss_skips_missing_base_score():

    severity_data = [
        {
            "type": "CVSS_V3",
            "score": (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                "S:U/C:H/I:H/A:H"
            ),
        }
    ]

    result = _convert_osv_cvss(severity_data)

    assert result is None


def test_convert_osv_cvss_maps_high_severity():

    severity_data = [
        {
            "type": "CVSS_V3",
            "score": (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                "S:U/C:H/I:N/A:N"
            ),
            "base_score": 7.5,
        }
    ]

    result = _convert_osv_cvss(severity_data)

    assert result.score == 7.5
    assert result.severity == "high"


def test_convert_osv_cvss_maps_medium_severity():

    severity_data = [
        {
            "type": "CVSS_V3",
            "score": (
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/"
                "S:U/C:L/I:N/A:N"
            ),
            "base_score": 5.0,
        }
    ]

    result = _convert_osv_cvss(severity_data)

    assert result.score == 5.0
    assert result.severity == "medium"


def test_convert_osv_cvss_maps_low_severity():

    severity_data = [
        {
            "type": "CVSS_V3",
            "score": (
                "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/"
                "S:U/C:L/I:N/A:N"
            ),
            "base_score": 2.0,
        }
    ]

    result = _convert_osv_cvss(severity_data)

    assert result.score == 2.0
    assert result.severity == "low"


def test_convert_osv_cvss_skips_invalid_cvss_v3_and_uses_next():

    severity_data = [
        {
            "type": "CVSS_V3",
            "score": None,
            "base_score": None,
        },
        {
            "type": "CVSS_V3",
            "score": (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                "S:U/C:H/I:H/A:H"
            ),
            "base_score": 10.0,
        },
    ]

    result = _convert_osv_cvss(severity_data)

    assert isinstance(result, CVSS)
    assert result.score == 10.0
    assert result.version == "3.1"


def test_convert_osv_cvss_uses_first_valid_cvss_v3():

    severity_data = [
        {
            "type": "CVSS_V3",
            "score": (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                "S:U/C:H/I:H/A:H"
            ),
            "base_score": 10.0,
        },
        {
            "type": "CVSS_V3",
            "score": (
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/"
                "S:U/C:L/I:N/A:N"
            ),
            "base_score": 5.0,
        },
    ]

    result = _convert_osv_cvss(severity_data)

    assert result.score == 10.0
    assert result.severity == "critical"


def test_convert_osv_cvss_skips_malformed_vector():

    severity_data = [
        {
            "type": "CVSS_V3",
            "score": "not-a-cvss-vector",
            "base_score": 7.5,
        }
    ]

    result = _convert_osv_cvss(severity_data)

    assert result is None


def test_convert_osv_cvss_skips_missing_cvss_version():

    severity_data = [
        {
            "type": "CVSS_V3",
            "score": (
                "/AV:N/AC:L/PR:N/UI:N/"
                "S:U/C:H/I:H/A:H"
            ),
            "base_score": 9.8,
        }
    ]

    result = _convert_osv_cvss(severity_data)

    assert result is None


def test_convert_osv_cvss_skips_unsupported_cvss_version():

    severity_data = [
        {
            "type": "CVSS_V3",
            "score": "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "base_score": 7.5,
        }
    ]

    result = _convert_osv_cvss(severity_data)

    assert result is None


def test_convert_osv_cvss_skips_invalid_base_score():

    severity_data = [
        {
            "type": "CVSS_V3",
            "score": (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                "S:U/C:H/I:H/A:H"
            ),
            "base_score": "not-a-score",
        }
    ]

    result = _convert_osv_cvss(severity_data)

    assert result is None


def test_convert_osv_cvss_skips_non_numeric_base_score():

    severity_data = [
        {
            "type": "CVSS_V3",
            "score": (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                "S:U/C:H/I:H/A:H"
            ),
            "base_score": None,
        },
        {
            "type": "CVSS_V3",
            "score": (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                "S:U/C:H/I:H/A:H"
            ),
            "base_score": "7.5",
        },
    ]

    result = _convert_osv_cvss(severity_data)

    assert result is not None
    assert result.score == 7.5
