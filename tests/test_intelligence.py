import pytest
from lib.vulnerability import VulnerabilityIntelligence
from lib.intelligence import (
    IntelligenceProvider,
    StaticIntelligenceProvider
)


class TestProvider(IntelligenceProvider):

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

        def get(self, vulnerability_id):
            return None

    provider = TestProvider()

    result = provider.get("CVE-2026-9999")
    assert result is None


def test_intelligence_provider_get_receives_vulnerability_id():

    class TestProvider(IntelligenceProvider):

        def __init__(self):
            self.received_id = None

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
