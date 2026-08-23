import requests
from lib.vulnerability import _validate_vulnerability_id


class OSVClient:
    """
    Client for retrieving vulnerability records from the OSV API.
    """

    def __init__(self, transport=None):
        self.transport = transport or OSVHTTPTransport()

    def get(self, vulnerability_id):
        """
        Retrieve an OSV vulnerability record.
        """

        vulnerability_id = _validate_vulnerability_id(
            vulnerability_id
        )

        if self.transport is None:
            raise ValueError(
                "OSV client requires a transport."
            )

        return self.transport.get(
            vulnerability_id
        )


class OSVHTTPTransport:
    """
    HTTP transport for the OSV API.
    """

    def __init__(
        self,
        base_url="https://api.osv.dev/v1",
        session=None,
        timeout=10,
    ):
        if not isinstance(base_url, str):
            raise ValueError(
                "OSV base URL must be a string."
            )

        base_url = base_url.strip()

        if not base_url:
            raise ValueError(
                "OSV base URL cannot be empty."
            )

        if not isinstance(timeout, (int, float)) or isinstance(
            timeout,
            bool,
        ):
            raise ValueError(
                "OSV timeout must be a number."
            )

        if timeout <= 0:
            raise ValueError(
                "OSV timeout must be greater than zero."
            )

        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.timeout = timeout

    def _build_url(self, vulnerability_id):
        """
        Build the OSV vulnerability endpoint URL.
        """

        vulnerability_id = _validate_vulnerability_id(
            vulnerability_id
        )

        return (
            f"{self.base_url}/vulns/{vulnerability_id}"
        )
        
    def get(self, vulnerability_id):
        """
        Retrieve an OSV vulnerability record over HTTP.
        """

        vulnerability_id = _validate_vulnerability_id(
            vulnerability_id
        )

        url = self._build_url(
            vulnerability_id
        )

        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
            )
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(
                "Failed to retrieve vulnerability intelligence " \
                "from OSV."
            ) from exc

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            if (
                getattr(exc.response, "status_code", None) == 404
                or "404" in str(exc)
            ):
                return None
            raise

        try:
            record = response.json()
        except ValueError as exc:
            raise ValueError(
                "OSV API returned invalid JSON."
            ) from exc

        if not isinstance(record, dict):
            raise ValueError(
                "OSV response must be a JSON object."
            )

        return record
