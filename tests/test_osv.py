import pytest
import requests

from lib.osv import (
    OSVClient,
    OSVHTTPTransport,
)
from lib.intelligence import (
    OSVIntelligenceProvider,
    VulnerabilityIntelligence,
)


# ============================================================
# OSVClient
# ============================================================

def test_osv_client_can_be_instantiated():

    client = OSVClient()

    assert client is not None


def test_osv_client_has_get_method():

    client = OSVClient()

    assert hasattr(client, "get")


def test_osv_client_has_default_transport():

    client = OSVClient()

    assert client.transport is not None


def test_osv_client_uses_default_transport():

    client = OSVClient()

    assert isinstance(
        client.transport,
        OSVHTTPTransport,
    )


def test_osv_client_validates_vulnerability_id():

    client = OSVClient()

    with pytest.raises(ValueError):
        client.get("not-a-vulnerability-id")


def test_osv_client_normalizes_vulnerability_id():

    class FakeTransport:

        def __init__(self):
            self.received_id = None

        def get(self, vulnerability_id):
            self.received_id = vulnerability_id
            return None

    transport = FakeTransport()

    client = OSVClient(
        transport=transport,
    )

    result = client.get(
        "cve-2021-44228"
    )

    assert result is None
    assert transport.received_id == (
        "CVE-2021-44228"
    )


def test_osv_client_returns_transport_record():

    expected_record = {
        "id": "CVE-2021-44228",
        "summary": "Log4Shell",
    }

    class FakeTransport:

        def get(self, vulnerability_id):
            assert vulnerability_id == (
                "CVE-2021-44228"
            )
            return expected_record

    client = OSVClient(
        transport=FakeTransport(),
    )

    result = client.get(
        "CVE-2021-44228"
    )

    assert result == expected_record


# ============================================================
# OSVHTTPTransport - construction and configuration
# ============================================================

def test_osv_http_transport_can_be_instantiated():

    transport = OSVHTTPTransport()

    assert transport is not None


def test_osv_http_transport_has_default_base_url():

    transport = OSVHTTPTransport()

    assert transport.base_url == (
        "https://api.osv.dev/v1"
    )


def test_osv_http_transport_has_default_session():

    transport = OSVHTTPTransport()

    assert transport.session is not None


def test_osv_http_transport_uses_injected_session():

    class FakeSession:
        pass

    session = FakeSession()

    transport = OSVHTTPTransport(
        session=session,
    )

    assert transport.session is session


def test_osv_http_transport_accepts_custom_base_url():

    transport = OSVHTTPTransport(
        base_url="https://example.com/osv",
    )

    assert transport.base_url == (
        "https://example.com/osv"
    )


def test_osv_http_transport_removes_trailing_slash_from_base_url():

    transport = OSVHTTPTransport(
        base_url="https://example.com/osv/",
    )

    assert transport.base_url == (
        "https://example.com/osv"
    )


# ============================================================
# OSVHTTPTransport - URL construction and validation
# ============================================================

def test_osv_http_transport_builds_vulnerability_url():

    transport = OSVHTTPTransport()

    url = transport._build_url(
        "CVE-2021-44228"
    )

    assert url == (
        "https://api.osv.dev/v1/"
        "vulns/CVE-2021-44228"
    )


def test_osv_http_transport_validates_vulnerability_id():

    class FakeSession:

        def get(self, url, timeout=None):
            raise AssertionError(
                "HTTP request should not be made."
            )

    transport = OSVHTTPTransport(
        session=FakeSession(),
    )

    with pytest.raises(ValueError):
        transport.get(
            "not-a-vulnerability-id"
        )


def test_osv_http_transport_normalizes_vulnerability_id():

    class FakeResponse:

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "id": "CVE-2021-44228",
            }

    class FakeSession:

        def __init__(self):
            self.received_url = None

        def get(self, url, timeout=None):
            self.received_url = url
            return FakeResponse()

    session = FakeSession()

    transport = OSVHTTPTransport(
        base_url="https://example.com/osv",
        session=session,
    )

    transport.get(
        "cve-2021-44228"
    )

    assert session.received_url == (
        "https://example.com/osv/"
        "vulns/CVE-2021-44228"
    )


# ============================================================
# OSVHTTPTransport - HTTP behavior
# ============================================================

def test_osv_http_transport_uses_get_request():

    class FakeResponse:

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "id": "CVE-2021-44228",
            }

    class FakeSession:

        def __init__(self):
            self.calls = []

        def get(self, url, timeout=None):
            self.calls.append(url)
            return FakeResponse()

    session = FakeSession()

    transport = OSVHTTPTransport(
        base_url="https://example.com/osv",
        session=session,
    )

    transport.get(
        "CVE-2021-44228"
    )

    assert session.calls == [
        "https://example.com/osv/"
        "vulns/CVE-2021-44228"
    ]


def test_osv_http_transport_gets_vulnerability_record():

    class FakeResponse:

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "id": "CVE-2021-44228",
                "summary": "Log4Shell",
            }

    class FakeSession:

        def __init__(self):
            self.received_url = None

        def get(self, url, timeout=None):
            self.received_url = url
            return FakeResponse()

    session = FakeSession()

    transport = OSVHTTPTransport(
        base_url="https://example.com/osv",
        session=session,
    )

    result = transport.get(
        "CVE-2021-44228"
    )

    assert result == {
        "id": "CVE-2021-44228",
        "summary": "Log4Shell",
    }

    assert session.received_url == (
        "https://example.com/osv/"
        "vulns/CVE-2021-44228"
    )


def test_osv_http_transport_returns_none_for_not_found():

    class FakeResponse:

        def raise_for_status(self):
            error = requests.exceptions.HTTPError(
                "404 Client Error"
            )
            error.response = self
            self.status_code = 404
            raise error

        def json(self):
            return {}

    class FakeSession:

        def get(self, url, timeout=None):
            return FakeResponse()

    transport = OSVHTTPTransport(
        base_url="https://example.com/osv",
        session=FakeSession(),
    )

    result = transport.get(
        "CVE-2021-44228"
    )

    assert result is None


def test_osv_http_transport_returns_json_object():

    class FakeResponse:

        def raise_for_status(self):
            pass

        def json(self):
            return [
                "not",
                "a",
                "record",
            ]

    class FakeSession:

        def get(self, url, timeout=None):
            return FakeResponse()

    transport = OSVHTTPTransport(
        base_url="https://example.com/osv",
        session=FakeSession(),
    )

    with pytest.raises(ValueError):
        transport.get(
            "CVE-2021-44228"
        )


def test_osv_http_transport_allows_empty_json_object():

    class FakeResponse:

        def raise_for_status(self):
            pass

        def json(self):
            return {}

    class FakeSession:

        def get(self, url, timeout=None):
            return FakeResponse()

    transport = OSVHTTPTransport(
        base_url="https://example.com/osv",
        session=FakeSession(),
    )

    result = transport.get(
        "CVE-2021-44228"
    )

    assert result == {}


# ============================================================
# OSVHTTPTransport - error handling
# ============================================================

def test_osv_http_transport_raises_for_http_errors():

    class FakeResponse:

        def raise_for_status(self):
            raise RuntimeError(
                "HTTP 500"
            )

        def json(self):
            return {}

    class FakeSession:

        def get(self, url, timeout=None):
            return FakeResponse()

    transport = OSVHTTPTransport(
        base_url="https://example.com/osv",
        session=FakeSession(),
    )

    with pytest.raises(RuntimeError):
        transport.get(
            "CVE-2021-44228"
        )


def test_osv_http_transport_propagates_transport_errors():

    class FakeSession:

        def get(self, url, timeout=None):
            raise RuntimeError(
                "connection failed"
            )

    transport = OSVHTTPTransport(
        base_url="https://example.com/osv",
        session=FakeSession(),
    )

    with pytest.raises(RuntimeError):
        transport.get(
            "CVE-2021-44228"
        )


# ============================================================
# OSVIntelligenceProvider - intelligence extraction
# ============================================================

def test_osv_intelligence_provider_uses_osv_client():

    class FakeTransport:

        def get(self, vulnerability_id):
            return {
                "id": vulnerability_id,
                "summary": (
                    "Example vulnerability."
                ),
                "details": (
                    "Detailed vulnerability "
                    "description."
                ),
                "published": (
                    "2026-01-15T12:00:00Z"
                ),
                "modified": (
                    "2026-08-01T12:00:00Z"
                ),
                "database_specific": {
                    "cwe_ids": [
                        "CWE-79",
                    ],
                },
                "references": [
                    {
                        "url": (
                            "https://example.com/"
                            "advisory"
                        ),
                    },
                ],
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": (
                            "CVSS:3.1/"
                            "AV:N/AC:L/PR:N/UI:N/"
                            "S:U/C:H/I:H/A:H"
                        ),
                        "base_score": 9.8,
                    },
                ],
            }

    client = OSVClient(
        transport=FakeTransport(),
    )

    provider = OSVIntelligenceProvider(
        client=client,
    )

    result = provider.get(
        "CVE-2026-1234"
    )

    assert isinstance(
        result,
        VulnerabilityIntelligence,
    )

    assert result.vulnerability_id == (
        "CVE-2026-1234"
    )

    assert result.description == (
        "Detailed vulnerability description."
    )

    assert result.cwe == [
        "CWE-79",
    ]

    assert result.cvss is not None
    assert result.cvss.version == "3.1"
    assert result.cvss.score == 9.8
    assert result.cvss.severity == "critical"

    assert result.published is not None
    assert result.modified is not None

    assert result.references == [
        "https://example.com/advisory"
    ]


# ============================================================
# OSVIntelligenceProvider - caching
# ============================================================

def test_osv_intelligence_provider_caches_results():

    class FakeClient:

        def __init__(self):
            self.calls = 0

        def get(self, vulnerability_id):
            self.calls += 1

            return {
                "id": vulnerability_id,
                "summary": (
                    "Example vulnerability."
                ),
            }

    client = FakeClient()

    provider = OSVIntelligenceProvider(
        client=client,
    )

    first = provider.get(
        "CVE-2026-1234"
    )

    second = provider.get(
        "CVE-2026-1234"
    )

    assert first is not None
    assert second is not None
    assert client.calls == 1


def test_osv_intelligence_provider_cache_uses_normalized_id():

    class FakeClient:

        def __init__(self):
            self.calls = 0

        def get(self, vulnerability_id):
            self.calls += 1

            return {
                "id": vulnerability_id,
                "summary": (
                    "Example vulnerability."
                ),
            }

    client = FakeClient()

    provider = OSVIntelligenceProvider(
        client=client,
    )

    provider.get(
        "cve-2026-1234"
    )

    provider.get(
        "CVE-2026-1234"
    )

    assert client.calls == 1


def test_osv_intelligence_provider_caches_not_found_results():

    class FakeClient:

        def __init__(self):
            self.calls = 0

        def get(self, vulnerability_id):
            self.calls += 1
            return None

    client = FakeClient()

    provider = OSVIntelligenceProvider(
        client=client,
    )

    first = provider.get(
        "CVE-2026-9999"
    )

    second = provider.get(
        "CVE-2026-9999"
    )

    assert first is None
    assert second is None
    assert client.calls == 1


def test_osv_intelligence_provider_caches_each_vulnerability_separately():

    class FakeClient:

        def __init__(self):
            self.calls = []

        def get(self, vulnerability_id):
            self.calls.append(
                vulnerability_id
            )

            return {
                "id": vulnerability_id,
                "summary": (
                    "Example vulnerability."
                ),
            }

    client = FakeClient()

    provider = OSVIntelligenceProvider(
        client=client,
    )

    provider.get(
        "CVE-2026-1234"
    )

    provider.get(
        "CVE-2026-5678"
    )

    provider.get(
        "CVE-2026-1234"
    )

    assert client.calls == [
        "CVE-2026-1234",
        "CVE-2026-5678",
    ]


# ============================================================
# OSVIntelligenceProvider - aliases
# ============================================================

def test_osv_intelligence_provider_converts_aliases():

    class FakeClient:

        def get(self, vulnerability_id):
            return {
                "id": "CVE-2021-44228",
                "summary": "Log4Shell",
                "aliases": [
                    "GHSA-jfh8-c2jp-5v3q",
                    "cve-2021-44228",
                ],
            }

    provider = OSVIntelligenceProvider(
        client=FakeClient(),
    )

    result = provider.get(
        "CVE-2021-44228"
    )

    assert result.aliases == [
        "GHSA-JFH8-C2JP-5V3Q",
        "CVE-2021-44228",
    ]
