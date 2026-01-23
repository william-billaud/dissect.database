import pytest

from dissect.database.ese.ntds.objects.dnsnode import DnsRecord, _parse_dns_name


@pytest.mark.parametrize(
    ("data", "expected_output"),
    [(b"\x03\x0ckingslanding\rsevenkingdoms\x05local", "kingslanding.sevenkingdoms.local")],
)
def test_parse_dns_name(data: bytes, expected_output: str) -> None:
    assert _parse_dns_name(data) == expected_output


@pytest.mark.parametrize(
    ("data", "expected_output"), [(b"\x11\x03\x06dc2-eu\x04test\x03lan\x00", "dc2-eu.test.lan.")], ids=["odd_length"]
)
def test_parse_dns_node_name(data: bytes, expected_output: str) -> None:
    assert DnsRecord._parse_node_name_record(data).name_node == expected_output
