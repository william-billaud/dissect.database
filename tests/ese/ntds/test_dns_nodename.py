from __future__ import annotations

import datetime
import typing

import pytest

from dissect.database.ese.ntds.objects.dnsnode import DnsRecord

if typing.TYPE_CHECKING:
    from dissect.database.ese.ntds.objects.dnsnode import SOARecord, SRVRecord

@pytest.mark.parametrize(
    ("data", "expected_output"),
    [(b"\x03\x0ckingslanding\rsevenkingdoms\x05local", "kingslanding.sevenkingdoms.local")],
)
def test_parse_dns_name(data: bytes, expected_output: str) -> None:
    assert DnsRecord._parse_dns_name(data) == expected_output


@pytest.mark.parametrize(
    ("data", "expected_output"), [(b"\x11\x03\x06dc2-eu\x04test\x03lan\x00", "dc2-eu.test.lan.")], ids=["odd_length"]
)
def test_parse_dns_node_name(data: bytes, expected_output: str) -> None:
    assert DnsRecord._parse_node_name_record(data).name_node == expected_output


def test_parse_dns_tombstoned_record() -> None:
    assert DnsRecord._parse_tombstoned_record(b"\xf1\xba\x0c\xa5\xc8 \xdc\x01").entombed_time == datetime.datetime(
        2025, 9, 8, 13, 58, 24, 889522, tzinfo=datetime.timezone.utc
    )


def test_parse_dns_string_record() -> None:
    assert DnsRecord._parse_string_record(b"\xf1\xba\x0c\xa5\xc8 \xdc\x01").entombed_time == datetime.datetime(
        2025, 9, 8, 13, 58, 24, 889522, tzinfo=datetime.timezone.utc
    )


def test_parse_dns_soa_record() -> None:
    pass


def test_parse_dns_srv_record() -> None:
    srv_record: SRVRecord = DnsRecord._parse_srv_record(b"\x00\x00\x00d\x01\x85\x10\x03\x04dc01\x03twi\x05local\x00")
    assert srv_record.priority == 0
    assert srv_record.weight == 100
    assert srv_record.port == 389  # LDAP
    assert srv_record.name_target == "dc01.twi.local."


def test_parse_name_preference_record() -> None:
    soa_record: SOARecord = DnsRecord._parse_soa_record(
        b"\x00\x00\x00\x1a\x00\x00\x03\x84\x00\x00\x02X\x00\x01Q\x80\x00\x00\x0e\x10\x10\x03\x04dc01\x03twi\x05local\x00\x16\x03\nhostmaster\x03twi\x05local\x00"
    )
    assert soa_record.name_primary_server == "dc01.twi.local."
    assert soa_record.serial == 26
    assert soa_record.refresh == 900
    assert soa_record.retry == 600
    assert soa_record.minimum_ttl == 3600
    assert soa_record.zone_administrator_email == "hostmaster.twi.local."



def test_parse_name_aaaa_record() -> None:
    pass


def test_parse_name_a_record() -> None:
    assert DnsRecord._parse_a_record(b"\xc0\xa8d\x1d").ipv4_address == "192.168.100.29"
    # Error
    assert DnsRecord._parse_a_record(b"\xc0") is None
