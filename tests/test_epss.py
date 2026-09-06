import pytest
import requests

from lib.epss import (
    EPSSClient,
    EPSSHTTPTransport,
)


class FakeResponse:
    def __init__(
        self,
        status_code=200,
        json_data=None,
        raise_error=None,
    ):
        self.status_code = status_code
        self.json_data = json_data
        self.raise_error = raise_error

    def raise_for_status(self):
        if self.raise_error is not None:
            raise self.raise_error

    def json(self):
        if isinstance(self.json_data, Exception):
            raise self.json_data

        return self.json_data


class FakeSession:
    def __init__(self, response=None, exception=None):
        self.response = response
        self.exception = exception
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(
            {
                "url": url,
                "kwargs": kwargs,
            }
        )

        if self.exception is not None:
            raise self.exception

        return self.response


def test_epss_transport_defaults():
    transport = EPSSHTTPTransport()

    assert transport.base_url == (
        "https://api.first.org/data/v1"
    )
    assert transport.timeout == 10
    assert transport.session is not None


def test_epss_transport_rejects_invalid_base_url():
    with pytest.raises(ValueError):
        EPSSHTTPTransport(base_url="")

    with pytest.raises(ValueError):
        EPSSHTTPTransport(base_url=None)


def test_epss_transport_rejects_invalid_timeout():
    with pytest.raises(ValueError):
        EPSSHTTPTransport(timeout=0)

    with pytest.raises(ValueError):
        EPSSHTTPTransport(timeout=-1)

    with pytest.raises(ValueError):
        EPSSHTTPTransport(timeout=True)


def test_epss_transport_builds_url():
    transport = EPSSHTTPTransport(
        base_url="https://example.test/data/v1/"
    )

    assert transport._build_url() == (
        "https://example.test/data/v1/epss"
    )


def test_epss_transport_gets_response():
    response = FakeResponse(
        json_data={
            "status": "OK",
            "total": 1,
            "data": [
                {
                    "cve": "CVE-2026-1234",
                    "epss": "0.500000000",
                    "percentile": "0.900000000",
                    "date": "2026-09-06",
                }
            ],
        }
    )

    session = FakeSession(response=response)

    transport = EPSSHTTPTransport(
        base_url="https://example.test/data/v1",
        session=session,
        timeout=15,
    )

    result = transport.get("CVE-2026-1234")

    assert result["status"] == "OK"

    assert len(session.calls) == 1
    assert session.calls[0]["url"] == (
        "https://example.test/data/v1/epss"
    )
    assert session.calls[0]["kwargs"]["params"] == {
        "cve": "CVE-2026-1234"
    }
    assert session.calls[0]["kwargs"]["timeout"] == 15


def test_epss_transport_converts_request_exception():
    session = FakeSession(
        exception=requests.exceptions.Timeout()
    )

    transport = EPSSHTTPTransport(
        session=session
    )

    with pytest.raises(
        RuntimeError,
        match="Failed to retrieve vulnerability intelligence from EPSS",
    ):
        transport.get("CVE-2026-1234")


def test_epss_transport_rejects_invalid_json():
    response = FakeResponse(
        json_data=ValueError("invalid json")
    )

    session = FakeSession(response=response)

    transport = EPSSHTTPTransport(
        session=session
    )

    with pytest.raises(
        ValueError,
        match="Invalid JSON response from EPSS",
    ):
        transport.get("CVE-2026-1234")


def test_epss_transport_rejects_non_dictionary_json():
    response = FakeResponse(
        json_data=[]
    )

    session = FakeSession(response=response)

    transport = EPSSHTTPTransport(
        session=session
    )

    with pytest.raises(
        ValueError,
        match="Invalid EPSS response structure",
    ):
        transport.get("CVE-2026-1234")


def test_epss_client_returns_record():
    record = {
        "cve": "CVE-2026-1234",
        "epss": "0.500000000",
        "percentile": "0.900000000",
        "date": "2026-09-06",
    }

    class FakeTransport:
        def get(self, vulnerability_id):
            return {
                "status": "OK",
                "total": 1,
                "data": [record],
            }

    client = EPSSClient(
        transport=FakeTransport()
    )

    assert client.get("CVE-2026-1234") == record


def test_epss_client_returns_none_when_no_record():
    class FakeTransport:
        def get(self, vulnerability_id):
            return {
                "status": "OK",
                "total": 0,
                "data": [],
            }

    client = EPSSClient(
        transport=FakeTransport()
    )

    assert client.get("CVE-2026-1234") is None


def test_epss_client_rejects_invalid_status():
    class FakeTransport:
        def get(self, vulnerability_id):
            return {
                "status": "ERROR",
                "total": 0,
                "data": [],
            }

    client = EPSSClient(
        transport=FakeTransport()
    )

    with pytest.raises(
        ValueError,
        match="Invalid EPSS response status",
    ):
        client.get("CVE-2026-1234")


def test_epss_client_rejects_invalid_data():
    class FakeTransport:
        def get(self, vulnerability_id):
            return {
                "status": "OK",
                "total": 1,
                "data": {},
            }

    client = EPSSClient(
        transport=FakeTransport()
    )

    with pytest.raises(
        ValueError,
        match="Invalid EPSS response data",
    ):
        client.get("CVE-2026-1234")


def test_epss_client_rejects_multiple_records():
    class FakeTransport:
        def get(self, vulnerability_id):
            return {
                "status": "OK",
                "total": 2,
                "data": [
                    {
                        "cve": "CVE-2026-1234",
                    },
                    {
                        "cve": "CVE-2026-5678",
                    },
                ],
            }

    client = EPSSClient(
        transport=FakeTransport()
    )

    with pytest.raises(
        ValueError,
        match="unexpected number of records",
    ):
        client.get("CVE-2026-1234")


def test_epss_client_rejects_mismatched_cve():
    class FakeTransport:
        def get(self, vulnerability_id):
            return {
                "status": "OK",
                "total": 1,
                "data": [
                    {
                        "cve": "CVE-2026-5678",
                        "epss": "0.5",
                        "percentile": "0.9",
                        "date": "2026-09-06",
                    }
                ],
            }

    client = EPSSClient(
        transport=FakeTransport()
    )

    with pytest.raises(
        ValueError,
        match="does not match request",
    ):
        client.get("CVE-2026-1234")
