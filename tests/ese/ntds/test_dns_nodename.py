from __future__ import annotations

import datetime
import typing

from dissect.database.ese.ntds.objects.dnsnode import DnsRecord

if typing.TYPE_CHECKING:
    from dissect.database.ese.ntds.objects.dnsnode import NamePreferenceRecord, SOARecord, SRVRecord


def test_parse_dns_name() -> None:
    assert (
        DnsRecord._parse_dns_name(b"\x03\x0ckingslanding\rsevenkingdoms\x05local") == "kingslanding.sevenkingdoms.local"
    )

    assert (
        DnsRecord._parse_dns_name(b"\x06\x04test\x04with\x08multiple\x06secion\rsevenkingdoms\x05local")
        == "test.with.multiple.secion.sevenkingdoms.local"
    )


def test_parse_dns_node_name_record() -> None:
    """Test a NodeName records (CNAME, PTR etc...)."""
    assert (
        DnsRecord._parse_node_name_record(b"\x11\x03\x06dc2-eu\x04test\x03lan\x00").name_node == "dc2-eu.test.lan"
    )  # odd length

    assert (
        DnsRecord._parse_node_name_record(b"&\x04\nWINTERFELL\x05north\rsevenkingdoms\x05local\x00").name_node
        == "WINTERFELL.north.sevenkingdoms.local"
    )

    assert (
        DnsRecord._parse_node_name_record(
            b"/\x06\x04test\x04with\x08multiple\x06secion\rsevenkingdoms\x05local\x00"
        ).name_node
        == "test.with.multiple.secion.sevenkingdoms.local"
    )


def test_parse_dns_tombstoned_record() -> None:
    assert DnsRecord._parse_tombstoned_record(b"\xf1\xba\x0c\xa5\xc8 \xdc\x01").entombed_time == datetime.datetime(
        2025, 9, 8, 13, 58, 24, 889522, tzinfo=datetime.timezone.utc
    )


def test_parse_dns_string_record() -> None:
    assert DnsRecord._parse_string_record(
        b"|TXT record made for dissect. Quite long to test if there is some limit size, "
        b"like over 64 characters or something like that.\x004Two new line above, "
        b"and an special char (euro) : \xe2\x82\xac"
    ).stringData == (
        "TXT record made for dissect. Quite long to test if there is some limit size, "
        "like over 64 characters or something like that.\n"
        "Two new line above, and an special char (euro) : €"
    )


def test_parse_dns_string_null_record() -> None:
    """Test an empty TXT record."""
    assert DnsRecord._parse_string_record(b"\x00").stringData == ""


def test_parse_name_preference_record() -> None:
    """Test with MX records, with two different preferences."""
    mx_record: NamePreferenceRecord = DnsRecord._parse_name_preference_record(b"\x00\x14\x0b\x01\tmailhost2\x00")
    assert mx_record.name_exchange == "mailhost2"
    assert mx_record.preference == 20

    mx_record: NamePreferenceRecord = DnsRecord._parse_name_preference_record(b"\x00\n\x0b\x01\tmailhost1\x00")
    assert mx_record.name_exchange == "mailhost1"
    assert mx_record.preference == 10


def test_parse_dns_srv_record() -> None:
    """Parse an SRV record related to LDAP."""
    srv_record: SRVRecord = DnsRecord._parse_srv_record(
        b"\x00\x00\x00d\x01\x85&\x04\nwinterfell\x05north\rsevenkingdoms\x05local\x00"
    )
    assert srv_record.priority == 0
    assert srv_record.weight == 100
    assert srv_record.port == 389  # LDAP
    assert srv_record.name_target == "winterfell.north.sevenkingdoms.local"


def test_parse_dns_soa_record() -> None:
    soa_record: SOARecord = DnsRecord._parse_soa_record(
        b'\x00\x00\x00#\x00\x00\x03\x84\x00\x00\x02X\x00\x01Q\x80\x00\x00\x0e\x10"\x03\x0ckingslanding\r'
        b"sevenkingdoms\x05local\x00 \x03\nhostmaster\rsevenkingdoms\x05local\x00"
    )
    assert soa_record.name_primary_server == "kingslanding.sevenkingdoms.local"
    assert soa_record.serial == 35
    assert soa_record.refresh == 900
    assert soa_record.retry == 600
    assert soa_record.minimum_ttl == 3600
    assert soa_record.zone_administrator_email == "hostmaster.sevenkingdoms.local"


def test_parse_name_aaaa_record() -> None:
    """Test multiple AAAA (IPv6) records."""
    assert (
        DnsRecord._parse_aaaa_record(b" \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00").ipv6_address
        == "2001:db8::1:0"
    )
    assert (
        DnsRecord._parse_aaaa_record(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01").ipv6_address
        == "::1"
    )
    assert (
        DnsRecord._parse_aaaa_record(b"\xfd\x17b\\\xf07\x00\x020\x84\x07n\x83\xeb\xab\x1b").ipv6_address
        == "fd17:625c:f037:2:3084:76e:83eb:ab1b"
    )


def test_parse_name_a_record() -> None:
    """Test an A (IpV4) record."""
    assert DnsRecord._parse_a_record(b"\xc0\xa8d\x1d").ipv4_address == "192.168.100.29"
    # Error
    assert DnsRecord._parse_a_record(b"\xc0") is None
