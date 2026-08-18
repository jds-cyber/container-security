import pytest
from datetime import datetime
from lib.vulnerability import (
    Vulnerability, 
    VulnerabilityIntelligence,
    CVSS,
)
from lib.intelligence import (
    IntelligenceProvider,
    StaticIntelligenceProvider,
    RecordIntelligenceProvider,
    enrich_vulnerabilities,
)


class TestProvider(IntelligenceProvider):

    @property
    def name(self):
        return "static"

    def get(self, vulnerability_id):
        return VulnerabilityIntelligence(
            vulnerability_id=vulnerability_id,
            description="Example vulnerability"
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


def test_static_intelligence_provider_returns_intelligence():

    intelligence = VulnerabilityIntelligence(
        "CVE-2026-20349",
        description="Cisco heap-based vulnerability."
    )

    provider = StaticIntelligenceProvider(
        intelligence=intelligence
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


def test_intelligence_provider_requires_name_implementation():

    class TestProvider(IntelligenceProvider):

        def get(self, vulnerability_id):
            return None

    with pytest.raises(TypeError):
        TestProvider()


def test_static_intelligence_provider_has_name():

    provider = StaticIntelligenceProvider()

    assert provider.name == "static"


def test_record_intelligence_provider_returns_intelligence():

    intelligence = VulnerabilityIntelligence(
        "CVE-2021-44228",
        description="A critical remote code execution (RCE) flaw in the Apache Log4j Java logging library."
    )

    provider = RecordIntelligenceProvider(
        records={
            "CVE-2021-44228": intelligence.to_dict()
        }
    )

    result = provider.get("CVE-2021-44228")

    assert isinstance(result, VulnerabilityIntelligence)
    assert result.vulnerability_id == "CVE-2021-44228"
    assert result.description == "A critical remote code execution (RCE) flaw in the Apache Log4j Java logging library."


def test_record_intelligence_provider_returns_none_when_not_found():

    provider = RecordIntelligenceProvider(
        records={}
    )

    result = provider.get("CVE-2021-44228")
    assert result is None


def test_record_intelligence_provider_preservers_metadata():

    intelligence = VulnerabilityIntelligence(
        "CVE-2014-6271",
        description="A vulnerability in the GNU Bash shell enabling remote code execution via environment variables.",
        cwe=["CWE-78"],
        references=["https://nvd.nist.gov/vuln/detail/cve-2014-6271"],
    )

    provider = RecordIntelligenceProvider(
        records={
            "CVE-2014-6271": intelligence.to_dict()
        }
    )

    result = provider.get("CVE-2014-6271")

    assert result.description == "A vulnerability in the GNU Bash shell enabling remote code execution via environment variables."
    assert result.cwe == ["CWE-78"]
    assert result.references == ["https://nvd.nist.gov/vuln/detail/cve-2014-6271"]


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


def test_static_intelligence_provider_returns_intelligence_for_vulnerability():

    intelligence = VulnerabilityIntelligence(
        "CVE-2017-0199",
        description="Microsoft Wordpad Remote Code Execution Vulnerability",
    )

    provider = StaticIntelligenceProvider(
        intelligence=intelligence
    )

    vulnerability = Vulnerability(
        "CVE-2017-0199"
    )

    result = provider.get(vulnerability.id)

    assert result is intelligence
    assert result.description == ("Microsoft Wordpad Remote Code Execution Vulnerability")


def test_enrich_vulnerabilities_loads_intelligence():

    intelligence = VulnerabilityIntelligence(
        "CVE-2017-0144",
        description="Windows SMBv1 Remote Code Execution Vulnerability"
    )

    provider = StaticIntelligenceProvider(
        intelligence=intelligence
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
                description="Java Applet Field Bytecode Verifier Cache Remote Code Execution"
            ).to_dict(),
        }
    )

    vulnerabilities = [
        Vulnerability("CVE-2017-0199"),
        Vulnerability("CVE-2012-1723")
    ]

    enrich_vulnerabilities(vulnerabilities, provider)

    assert vulnerabilities[0].intelligence is not None
    assert vulnerabilities[0].intelligence.vulnerability_id == "CVE-2017-0199"

    assert vulnerabilities[1].intelligence is not None
    assert vulnerabilities[1].intelligence.vulnerability_id == "CVE-2012-1723"


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

    assert vulnerabilities[0].intelligence.vulnerability_id == intelligence1.vulnerability_id
    assert vulnerabilities[1].intelligence.vulnerability_id == intelligence2.vulnerability_id

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


def test_record_intelligence_provider_reconstructs_cvss():

    cvss = CVSS(
        version="3.1",
        score=9.8,
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="critical"
    )

    intelligence = VulnerabilityIntelligence(
        "CVE-2021-44228",
        description="Log4Shell",
        cvss=cvss
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
