import pytest
from lib.vulnerability import VulnerabilityIntelligence
from lib.intelligence import (
    IntelligenceProvider,
    StaticIntelligenceProvider,
    RecordIntelligenceProvider,
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
