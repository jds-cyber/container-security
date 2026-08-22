import pytest
from lib.vulnerability import Vulnerability
from lib.scanner import (
    ScannerAdapter,
    GrypeAdapter,
    ScannerRegistry,
    parse_scan,
    create_default_registry,
    load_scan_report,
)


def test_scanner_adapter_cannot_be_instantiated():

    with pytest.raises(TypeError):
        ScannerAdapter()


def test_scanner_adapter_requires_name_implemented():

    class TestAdapter(ScannerAdapter):

        @property
        def formats(self):
            return ["json"]

        def parse(self, report):
            return []

    with pytest.raises(TypeError):
        TestAdapter()


def test_scanner_adapter_requires_parse_implemented():

    class TestAdapter(ScannerAdapter):

        @property
        def name(self):
            return "test"

        @property
        def formats(self):
            return ["json"]

    with pytest.raises(TypeError):
        TestAdapter()


def test_scanner_adapter_returns_vulnerabilities():

    class TestAdapter(ScannerAdapter):

        @property
        def name(self):
            return "NVD"

        @property
        def formats(self):
            pass

        def parse(self, report):
            return [
                Vulnerability(
                    "CVE-2019-11510",
                    description="Pulse Secure Pulse Connect Secure SSL VPN Unauthenticated Path",
                    severity="high"
                ),
            ]

    adapter = TestAdapter()

    result = adapter.parse({})

    assert len(result) == 1
    assert isinstance(result[0], Vulnerability)
    assert result[0].id == "CVE-2019-11510"
    assert result[0].description == "Pulse Secure Pulse Connect Secure SSL VPN Unauthenticated Path"


def test_grype_adapter_has_name():

    adapter = GrypeAdapter()
    assert adapter.name == "grype"


def test_grype_adapter_supports_json():

    adapter = GrypeAdapter()
    assert "json" in adapter.formats


def test_grype_adapter_parses_vulnerability():

    adapter = GrypeAdapter()

    report = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2021-44228",
                    "severity": "Critical",
                    "fix": {
                        "versions": ["2.17.1"]
                    },
                },
                "artifact": {
                    "name": "log4j-core",
                    "version": "2.14.1",
                },
            }
        ]
    }

    result = adapter.parse(report)

    assert len(result) == 1
    assert isinstance(result[0], Vulnerability)

    assert result[0].id == "CVE-2021-44228"
    assert result[0].severity == "critical"
    assert result[0].installed_version == "2.14.1"
    assert result[0].fixed_version == "2.17.1"


def test_grype_adapter_skips_match_without_vulnerability_id():

    adapter = GrypeAdapter()

    report = {
        "matches": [
            {
                "vulnerability": {},
                "artifact": {
                    "name": "example",
                    "versions": "1.0.0",
                },
            }
        ]
    }

    result = adapter.parse(report)

    assert result == []


def test_grype_adapter_parses_vulnerability_without_fix():

    adapter = GrypeAdapter()

    report = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2026-1234",
                    "severity": "High",
                },
                "artifact": {
                    "name": "openssl",
                    "version": "3.0.2",
                },
            }
        ]
    }

    result = adapter.parse(report)

    assert len(result) == 1
    assert isinstance(result[0], Vulnerability)

    assert result[0].id == "CVE-2026-1234"
    assert result[0].severity == "high"
    assert result[0].package == "openssl"
    assert result[0].installed_version == "3.0.2"
    assert result[0].fixed_version is None


def test_grype_adapter_handles_empty_fix_versions():

    adapter = GrypeAdapter()

    report = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2026-9999",
                    "severity": "High",
                    "fix": {
                        "versions": [],
                        "state": "not-fixed",
                    },
                },
                "artifact": {
                    "name": "example",
                    "version": "1.0.0",
                },
            }
        ]
    }

    result = adapter.parse(report)

    assert len(result) == 1
    assert result[0].id == "CVE-2026-9999"
    assert result[0].fixed_version is None


def test_scanner_registry_returns_none_for_unknown_scanner():

    registry = ScannerRegistry()
    adapter = registry.get("unknown")

    assert adapter is None
        

def test_scanner_registry_returns_none_when_scanner_not_provided():

    registry = ScannerRegistry()
    adapter = registry.get(None)
    
    assert adapter is None


def test_scanner_registry_can_register_new_adapter():

    class TestAdapter(ScannerAdapter):

        @property
        def name(self):
            return "test"

        @property
        def formats(self):
            pass

        def parse(self, report):
            return []

    registry = ScannerRegistry()

    adapter = TestAdapter()
    registry.register(adapter)

    result = registry.get("test")

    assert result is adapter
    assert result.name == "test"


def test_scanner_registry_rejects_non_adapter():

    registry = ScannerRegistry()

    with pytest.raises(ValueError):
        registry.register("not an adapter")


def test_scanner_registry_rejects_adapter_without_name():

    class TestAdapter(ScannerAdapter):

        @property
        def name(self):
            return ""

        @property
        def formats(self):
            pass

        def parse(self, report):
            return []

    registry = ScannerRegistry()

    with pytest.raises(ValueError):
        registry.register(TestAdapter())


def test_scanner_registry_replaces_existing_adapter():

    class ReplacementAdapter(ScannerAdapter):

        @property
        def name(self):
            return "grype"

        @property
        def formats(self):
            pass

        def parse(self, report):
            return []

    registry = ScannerRegistry()

    original = registry.get("grype")
    replacement = ReplacementAdapter()

    registry.register(replacement)

    result = registry.get("grype")

    assert result is replacement
    assert result is not original


def test_scanner_registry_can_start_empty():

    registry = ScannerRegistry()

    assert registry.get("grype") is None


def test_scanner_registry_can_register_grype():

    registry = ScannerRegistry()
    registry.register(GrypeAdapter())

    adapter = registry.get("grype")

    assert isinstance (adapter, GrypeAdapter)
    assert adapter.name == "grype"


def test_parse_scan_uses_registered_adapter():

    class TestAdapter(ScannerAdapter):

        @property
        def name(self):
            return "test"

        @property
        def formats(self):
            pass

        def parse(self, report):
            return [
                Vulnerability(
                    "CVE-2018-8174",
                    severity="critical",
                )
            ]

    registry = ScannerRegistry()
    adapter = TestAdapter()

    registry.register(adapter)

    result = parse_scan(
        registry,
        "test", 
        {},
    )

    assert len(result) == 1
    assert isinstance(result[0], Vulnerability)
    assert result[0].id == "CVE-2018-8174"


def test_parse_scan_rejects_unknown_scanner():

    registry = ScannerRegistry()

    with pytest.raises(ValueError):
        parse_scan(
            registry,
            "unknown",
            {},
        )


def test_default_registry_contains_grype():

    registry = create_default_registry()

    adapter = registry.get("grype")

    assert isinstance(adapter, GrypeAdapter)


def test_grype_adapter_rejects_invalid_report():

    adapter = GrypeAdapter()

    with pytest.raises(ValueError):
        adapter.parse({"invalid": []})


def test_load_scan_report_reads_json_file(tmp_path):

    report_file = tmp_path / "report.json"
    report_file.write_text(
        '{"matches": []}'
    )

    registry = ScannerRegistry()
    registry.register(GrypeAdapter())

    report = load_scan_report(
        registry,
        "grype",
        report_file,
    )

    assert report == {
        "matches": []
    }


def test_load_scan_report_rejects_invalid_json(tmp_path):

    report_file = tmp_path / "report.json"
    report_file.write_text(
        '{"matches": [broken}'
    )

    registry = ScannerRegistry()
    registry.register(GrypeAdapter())

    with pytest.raises(ValueError):
        load_scan_report(
            registry,
            "grype",
            report_file,
        )


def test_load_scan_report_rejects_missing_file(tmp_path):

    report_file = tmp_path / "missing.json"

    registry = ScannerRegistry()
    registry.register(GrypeAdapter())

    with pytest.raises(FileNotFoundError):
        load_scan_report(
            registry,
            "grype",
            report_file,
        )


def test_load_scan_report_rejects_unknown_format(tmp_path):

    report_file = tmp_path / "report.json"
    report_file.write_text('{"matches": []}')

    registry = ScannerRegistry()
    registry.register(GrypeAdapter())

    with pytest.raises(ValueError):
        load_scan_report(
            registry,
            "grype",
            tmp_path / "report.xml"
        )


def test_load_scan_report_uses_adapter_formats(tmp_path):

    report_file = tmp_path / "report.json"
    report_file.write_text(
        '{"matches": []}'
    )

    registry = ScannerRegistry()
    registry.register(GrypeAdapter())

    report = load_scan_report(
        registry,
        "grype",
        report_file,
    )

    assert report == {
        "matches": []
    }


def test_load_scan_report_rejects_format_not_supported_by_adapter(tmp_path):

    report_file = tmp_path / "report.xml"
    report_file.write_text("<report></report>")

    registry = ScannerRegistry()
    registry.register(GrypeAdapter())

    with pytest.raises(ValueError, match="Unsupported report format: xml"):
        load_scan_report(
            registry,
            "grype",
            report_file,
        )


def test_scanner_adapter_formats_are_available():

    class TestAdapter(ScannerAdapter):

        @property
        def name(self):
            return "test"

        @property
        def formats(self):
            return ["json"]

        def parse(self, report):
            return []

    adapter = TestAdapter()
    assert adapter.formats == ["json"]


def test_load_scan_report_accepts_uppercase_json_extension(tmp_path):

    report_file = tmp_path / "report.JSON"
    report_file.write_text(
        '{"matches": []}'
    )

    registry = ScannerRegistry()
    registry.register(GrypeAdapter())

    report = load_scan_report(
        registry,
        "grype",
        report_file,
    )

    assert report == {
        "matches": []
    }
