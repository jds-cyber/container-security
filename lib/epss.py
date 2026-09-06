import requests

from lib.vulnerability import _validate_vulnerability_id


class EPSSClient:
    """
    Client for retrieving EPSS vulnerability intelligence.
    """

    def __init__(self, transport=None):
        self.transport = transport or EPSSHTTPTransport()

    def get(self, vulnerability_id):
        """
        Retrieve a normalized EPSS record for a vulnerability ID.

        Returns:
            dict | None
        """

        _validate_vulnerability_id(vulnerability_id)

        if not hasattr(self.transport, "get"):
            raise ValueError("transport must provide a get method")

        response = self.transport.get(vulnerability_id)

        if not isinstance(response, dict):
            raise ValueError(
                "Invalid EPSS response structure."
            )

        if response.get("status") != "OK":
            raise ValueError(
                "Invalid EPSS response status."
            )

        data = response.get("data")

        if not isinstance(data, list):
            raise ValueError(
                "Invalid EPSS response data."
            )

        if not data:
            return None

        if len(data) != 1:
            raise ValueError(
                "EPSS response returned an unexpected number of records."
            )

        record = data[0]

        if not isinstance(record, dict):
            raise ValueError(
                "Invalid EPSS record."
            )

        if record.get("cve") != vulnerability_id:
            raise ValueError(
                "EPSS response vulnerability ID does not match request."
            )

        return record


class EPSSHTTPTransport:
    """
    HTTP transport for the FIRST EPSS API.
    """

    DEFAULT_BASE_URL = "https://api.first.org/data/v1"

    def __init__(
        self,
        base_url=DEFAULT_BASE_URL,
        session=None,
        timeout=10,
    ):
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError(
                "base_url must be a non-empty string"
            )

        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise ValueError(
                "timeout must be a positive number"
            )

        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.timeout = timeout

    def _build_url(self):
        """
        Build the EPSS API endpoint URL.
        """

        return "{}/epss".format(self.base_url)

    def get(self, vulnerability_id):
        """
        Retrieve EPSS data from FIRST.
        """

        _validate_vulnerability_id(vulnerability_id)

        url = self._build_url()

        try:
            response = self.session.get(
                url,
                params={"cve": vulnerability_id},
                timeout=self.timeout,
            )

        except requests.exceptions.RequestException as exc:
            raise RuntimeError(
                "Failed to retrieve vulnerability intelligence from EPSS."
            ) from exc

        response.raise_for_status()

        try:
            data = response.json()

        except ValueError as exc:
            raise ValueError(
                "Invalid JSON response from EPSS."
            ) from exc

        if not isinstance(data, dict):
            raise ValueError(
                "Invalid EPSS response structure."
            )

        return data
